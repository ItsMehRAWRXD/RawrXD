/**
 * @file titan_sdk.h
 * @brief RawrXD Titan SDK — Single-Header C API for Local LLM Inference
 * @version 1.0.0
 * @date 2026-06-10
 * 
 * This is the official SDK for integrating RawrXD's native inference engine
 * into third-party applications. Drop this header + RawrXD_Titan.dll into
 * your project and get local, streaming LLM inference in under 10 minutes.
 * 
 * ## Quick Start
 * ```c
 * #include "titan_sdk.h"
 * 
 * int main() {
 *     TitanContext* ctx = titan_init("model.gguf");
 *     if (!ctx) { fprintf(stderr, "Failed to load model\n"); return 1; }
 *     
 *     titan_generate_streaming(ctx, "Hello, world!", my_token_callback, NULL);
 *     
 *     titan_free(ctx);
 *     return 0;
 * }
 * ```
 * 
 * ## License
 * Proprietary — See LICENSE.txt for distribution terms
 */

#ifndef TITAN_SDK_H
#define TITAN_SDK_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* ============================================================================
 * Version
 * ============================================================================ */

#define TITAN_SDK_VERSION_MAJOR 1
#define TITAN_SDK_VERSION_MINOR 0
#define TITAN_SDK_VERSION_PATCH 0
#define TITAN_SDK_VERSION_STRING "1.0.0"

/* ============================================================================
 * Platform Detection
 * ============================================================================ */

#ifdef _WIN32
  #ifdef TITAN_SDK_BUILDING_DLL
    #define TITAN_API __declspec(dllexport)
  #else
    #define TITAN_API __declspec(dllimport)
  #endif
  #define TITAN_CALL __cdecl
#else
  #define TITAN_API __attribute__((visibility("default")))
  #define TITAN_CALL
#endif

/* ============================================================================
 * Opaque Handles
 * ============================================================================ */

/** @brief Inference context — holds model, tokenizer, KV cache */
typedef struct TitanContext TitanContext;

/** @brief Async generation handle — for canceling long-running inference */
typedef struct TitanGeneration TitanGeneration;

/* ============================================================================
 * Callbacks
 * ============================================================================ */

/**
 * @brief Called for each generated token during streaming inference
 * @param token The generated token string (UTF-8, null-terminated)
 * @param user_data User-provided pointer from titan_generate_streaming()
 * @return true to continue generation, false to abort
 */
typedef bool (TITAN_CALL *TitanTokenCallback)(const char* token, void* user_data);

/**
 * @brief Called when generation completes
 * @param user_data User-provided pointer
 */
typedef void (TITAN_CALL *TitanCompleteCallback)(void* user_data);

/**
 * @brief Called on error during generation
 * @param error Error message (UTF-8, null-terminated)
 * @param user_data User-provided pointer
 */
typedef void (TITAN_CALL *TitanErrorCallback)(const char* error, void* user_data);

/* ============================================================================
 * Configuration
 * ============================================================================ */

/** @brief Generation parameters */
typedef struct TitanConfig {
    /** Path to GGUF model file */
    const char* model_path;
    
    /** Context window size (0 = model default) */
    uint32_t context_length;
    
    /** Max tokens to generate (0 = 256) */
    uint32_t max_tokens;
    
    /** Temperature (0.0 = deterministic, 1.0 = creative) */
    float temperature;
    
    /** Top-K sampling (0 = disabled) */
    uint32_t top_k;
    
    /** Top-P sampling (0.0 = disabled, 1.0 = full) */
    float top_p;
    
    /** Random seed (0 = random) */
    uint32_t seed;
    
    /** Number of CPU threads (0 = auto) */
    uint32_t num_threads;
    
    /** Enable GPU acceleration (Vulkan/DirectX) */
    bool use_gpu;
    
    /** GPU layer count (0 = CPU only) */
    uint32_t gpu_layers;
    
    /** Quantization override (NULL = model default) */
    const char* quant_type;
    
    /** KV cache quantization (NULL = full precision) */
    const char* kv_quant_type;
    
    /** Verbosity level (0 = silent, 1 = errors, 2 = warnings, 3 = info) */
    uint32_t verbosity;
    
    /** Reserved for future use */
    void* reserved[8];
} TitanConfig;

/** @brief Default configuration */
static inline TitanConfig titan_default_config(void) {
    TitanConfig cfg = {0};
    cfg.model_path = NULL;
    cfg.context_length = 0;
    cfg.max_tokens = 256;
    cfg.temperature = 0.7f;
    cfg.top_k = 40;
    cfg.top_p = 0.9f;
    cfg.seed = 0;
    cfg.num_threads = 0;
    cfg.use_gpu = false;
    cfg.gpu_layers = 0;
    cfg.quant_type = NULL;
    cfg.kv_quant_type = NULL;
    cfg.verbosity = 1;
    return cfg;
}

/* ============================================================================
 * Lifecycle
 * ============================================================================ */

/**
 * @brief Initialize the Titan inference engine
 * @param config Model and generation configuration
 * @return Context handle, or NULL on error
 * 
 * This loads the GGUF model, initializes the tokenizer, and allocates
 * the KV cache. It is safe to call multiple times for different models.
 */
TITAN_API TitanContext* TITAN_CALL titan_init(const TitanConfig* config);

/**
 * @brief Free a Titan context and all associated resources
 * @param ctx Context handle (may be NULL)
 */
TITAN_API void TITAN_CALL titan_free(TitanContext* ctx);

/**
 * @brief Check if a context is valid and ready for inference
 * @param ctx Context handle
 * @return true if ready, false if not initialized or error
 */
TITAN_API bool TITAN_CALL titan_is_ready(const TitanContext* ctx);

/* ============================================================================
 * Synchronous Generation
 * ============================================================================ */

/**
 * @brief Generate text synchronously (blocking)
 * @param ctx Context handle
 * @param prompt Input prompt (UTF-8, null-terminated)
 * @param output Buffer for generated text
 * @param output_size Size of output buffer in bytes
 * @return Number of bytes written, or -1 on error
 * 
 * This is the simplest API — blocking, single-shot generation.
 * For streaming/real-time use, prefer titan_generate_streaming().
 */
TITAN_API int32_t TITAN_CALL titan_generate(
    TitanContext* ctx,
    const char* prompt,
    char* output,
    size_t output_size
);

/* ============================================================================
 * Streaming Generation
 * ============================================================================ */

/**
 * @brief Generate text with streaming callbacks (non-blocking)
 * @param ctx Context handle
 * @param prompt Input prompt (UTF-8, null-terminated)
 * @param token_cb Called for each generated token
 * @param complete_cb Called when generation completes (may be NULL)
 * @param error_cb Called on error (may be NULL)
 * @param user_data Passed to all callbacks
 * @return Generation handle, or NULL on error
 * 
 * This is the recommended API for interactive applications.
 * Generation runs on a background thread; callbacks are thread-safe.
 * 
 * Example:
 * ```c
 * static bool on_token(const char* token, void* user_data) {
 *     printf("%s", token);
 *     fflush(stdout);
 *     return true;  // Continue generation
 * }
 * 
 * TitanGeneration* gen = titan_generate_streaming(
 *     ctx, "Hello", on_token, NULL, NULL, NULL);
 * 
 * // ... do other work ...
 * 
 * titan_generation_wait(gen, 5000);  // Wait up to 5 seconds
 * titan_generation_free(gen);
 * ```
 */
TITAN_API TitanGeneration* TITAN_CALL titan_generate_streaming(
    TitanContext* ctx,
    const char* prompt,
    TitanTokenCallback token_cb,
    TitanCompleteCallback complete_cb,
    TitanErrorCallback error_cb,
    void* user_data
);

/**
 * @brief Cancel an in-progress generation
 * @param gen Generation handle
 * @return true if canceled, false if already complete
 */
TITAN_API bool TITAN_CALL titan_generation_cancel(TitanGeneration* gen);

/**
 * @brief Wait for generation to complete
 * @param gen Generation handle
 * @param timeout_ms Maximum time to wait (0 = infinite)
 * @return true if complete, false if timed out
 */
TITAN_API bool TITAN_CALL titan_generation_wait(TitanGeneration* gen, uint32_t timeout_ms);

/**
 * @brief Check if generation is still running
 * @param gen Generation handle
 * @return true if running, false if complete or error
 */
TITAN_API bool TITAN_CALL titan_generation_is_running(const TitanGeneration* gen);

/**
 * @brief Free a generation handle
 * @param gen Generation handle (may be NULL)
 * 
 * If generation is still running, it is canceled first.
 */
TITAN_API void TITAN_CALL titan_generation_free(TitanGeneration* gen);

/* ============================================================================
 * Chat / Conversation
 * ============================================================================ */

/** @brief Chat session handle */
typedef struct TitanChatSession TitanChatSession;

/**
 * @brief Create a new chat session
 * @param ctx Context handle
 * @param system_prompt System prompt (may be NULL)
 * @return Chat session handle, or NULL on error
 */
TITAN_API TitanChatSession* TITAN_CALL titan_chat_create(
    TitanContext* ctx,
    const char* system_prompt
);

/**
 * @brief Send a message and get streaming response
 * @param session Chat session handle
 * @param message User message (UTF-8, null-terminated)
 * @param token_cb Called for each response token
 * @param complete_cb Called when response completes (may be NULL)
 * @param error_cb Called on error (may be NULL)
 * @param user_data Passed to all callbacks
 * @return Generation handle, or NULL on error
 */
TITAN_API TitanGeneration* TITAN_CALL titan_chat_send(
    TitanChatSession* session,
    const char* message,
    TitanTokenCallback token_cb,
    TitanCompleteCallback complete_cb,
    TitanErrorCallback error_cb,
    void* user_data
);

/**
 * @brief Clear chat history
 * @param session Chat session handle
 */
TITAN_API void TITAN_CALL titan_chat_clear(TitanChatSession* session);

/**
 * @brief Free a chat session
 * @param session Chat session handle (may be NULL)
 */
TITAN_API void TITAN_CALL titan_chat_free(TitanChatSession* session);

/* ============================================================================
 * Tokenization
 * ============================================================================ */

/**
 * @brief Count tokens in a string without generating
 * @param ctx Context handle
 * @param text Input text (UTF-8, null-terminated)
 * @return Token count, or -1 on error
 */
TITAN_API int32_t TITAN_CALL titan_tokenize_count(
    TitanContext* ctx,
    const char* text
);

/**
 * @brief Convert token IDs back to text
 * @param ctx Context handle
 * @param tokens Array of token IDs
 * @param num_tokens Number of tokens
 * @param output Output buffer
 * @param output_size Size of output buffer
 * @return Number of bytes written, or -1 on error
 */
TITAN_API int32_t TITAN_CALL titan_detokenize(
    TitanContext* ctx,
    const int32_t* tokens,
    size_t num_tokens,
    char* output,
    size_t output_size
);

/* ============================================================================
 * Model Information
 * ============================================================================ */

/** @brief Model metadata */
typedef struct TitanModelInfo {
    /** Model name from GGUF metadata */
    char name[256];
    
    /** Architecture (e.g., "llama", "mistral", "phi") */
    char architecture[64];
    
    /** Parameter count (e.g., 7000000000 for 7B) */
    uint64_t parameter_count;
    
    /** Context window size */
    uint32_t context_length;
    
    /** Vocabulary size */
    uint32_t vocab_size;
    
    /** Embedding dimension */
    uint32_t embedding_dim;
    
    /** Number of layers */
    uint32_t num_layers;
    
    /** Number of attention heads */
    uint32_t num_heads;
    
    /** Quantization type (e.g., "Q4_0", "Q8_0", "F16") */
    char quantization[16];
    
    /** File size in bytes */
    uint64_t file_size;
    
    /** Memory required for inference (bytes) */
    uint64_t memory_required;
} TitanModelInfo;

/**
 * @brief Get model metadata
 * @param ctx Context handle
 * @param info Output structure
 * @return true on success, false on error
 */
TITAN_API bool TITAN_CALL titan_get_model_info(
    const TitanContext* ctx,
    TitanModelInfo* info
);

/* ============================================================================
 * Performance / Metrics
 * ============================================================================ */

/** @brief Performance metrics */
typedef struct TitanMetrics {
    /** Tokens generated per second */
    float tokens_per_second;
    
    /** Time to first token (milliseconds) */
    float time_to_first_token_ms;
    
    /** Total generation time (milliseconds) */
    float total_time_ms;
    
    /** Tokens generated */
    uint32_t tokens_generated;
    
    /** Current RAM usage (bytes) */
    uint64_t memory_usage_bytes;
    
    /** Peak RAM usage (bytes) */
    uint64_t peak_memory_bytes;
    
    /** Current GPU VRAM usage (bytes, 0 if CPU) */
    uint64_t gpu_memory_usage_bytes;
    
    /** CPU utilization (0.0 - 1.0) */
    float cpu_utilization;
    
    /** GPU utilization (0.0 - 1.0, 0 if CPU) */
    float gpu_utilization;
} TitanMetrics;

/**
 * @brief Get current performance metrics
 * @param ctx Context handle
 * @param metrics Output structure
 * @return true on success, false on error
 */
TITAN_API bool TITAN_CALL titan_get_metrics(
    const TitanContext* ctx,
    TitanMetrics* metrics
);

/**
 * @brief Reset performance metrics
 * @param ctx Context handle
 */
TITAN_API void TITAN_CALL titan_reset_metrics(TitanContext* ctx);

/* ============================================================================
 * Error Handling
 * ============================================================================ */

/**
 * @brief Get last error message
 * @return Error string (UTF-8, null-terminated). Do not free.
 */
TITAN_API const char* TITAN_CALL titan_get_last_error(void);

/**
 * @brief Set log callback for diagnostics
 * @param callback Called for each log message (may be NULL to disable)
 * @param min_level Minimum log level (0 = debug, 1 = info, 2 = warning, 3 = error)
 */
TITAN_API void TITAN_CALL titan_set_log_callback(
    void (TITAN_CALL *callback)(int level, const char* message),
    int min_level
);

/* ============================================================================
 * Advanced: KV Cache Management
 * ============================================================================ */

/**
 * @brief Save KV cache to disk for fast resumption
 * @param ctx Context handle
 * @param path File path for cache
 * @return true on success, false on error
 */
TITAN_API bool TITAN_CALL titan_kv_cache_save(
    TitanContext* ctx,
    const char* path
);

/**
 * @brief Load KV cache from disk
 * @param ctx Context handle
 * @param path File path for cache
 * @return true on success, false on error
 */
TITAN_API bool TITAN_CALL titan_kv_cache_load(
    TitanContext* ctx,
    const char* path
);

/**
 * @brief Clear KV cache (free memory)
 * @param ctx Context handle
 */
TITAN_API void TITAN_CALL titan_kv_cache_clear(TitanContext* ctx);

/* ============================================================================
 * Advanced: Speculative Decoding
 * ============================================================================ */

/**
 * @brief Enable speculative decoding with draft model
 * @param ctx Context handle
 * @param draft_model_path Path to smaller draft model (GGUF)
 * @param num_draft_tokens Number of tokens to draft per step (2-5)
 * @return true on success, false on error
 */
TITAN_API bool TITAN_CALL titan_enable_speculative(
    TitanContext* ctx,
    const char* draft_model_path,
    uint32_t num_draft_tokens
);

/**
 * @brief Disable speculative decoding
 * @param ctx Context handle
 */
TITAN_API void TITAN_CALL titan_disable_speculative(TitanContext* ctx);

/* ============================================================================
 * Version
 * ============================================================================ */

/**
 * @brief Get SDK version string
 * @return Version string (e.g., "1.0.0")
 */
TITAN_API const char* TITAN_CALL titan_version(void);

/**
 * @brief Check if DLL version matches header version
 * @return true if compatible, false if mismatch
 */
TITAN_API bool TITAN_CALL titan_check_version(void);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // TITAN_SDK_H
