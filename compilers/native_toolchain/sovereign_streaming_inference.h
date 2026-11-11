// sovereign_streaming_inference.h - Streaming Inference Engine
// Real-time token streaming with callbacks
// NO DEPENDENCIES - Pure Win32 API

#ifndef SOVEREIGN_STREAMING_INFERENCE_H
#define SOVEREIGN_STREAMING_INFERENCE_H

#include <stdint.h>
#include <stdbool.h>
#include "sovereign_unified_model_loader.h"

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// CONFIGURATION
// ============================================================================

#define SOVEREIGN_MAX_STREAM_TOKENS     8192
#define SOVEREIGN_MAX_STREAM_QUEUE      1024
#define SOVEREIGN_STREAM_BUFFER_SIZE    4096

// ============================================================================
// ENUMS
// ============================================================================

typedef enum {
    SOVEREIGN_STREAM_IDLE = 0,
    SOVEREIGN_STREAM_TOKENIZING,
    SOVEREIGN_STREAM_INFERRING,
    SOVEREIGN_STREAM_SAMPLING,
    SOVEREIGN_STREAM_DETOKENIZING,
    SOVEREIGN_STREAM_COMPLETE,
    SOVEREIGN_STREAM_ERROR,
    SOVEREIGN_STREAM_CANCELLED
} SovereignStreamState;

typedef enum {
    SOVEREIGN_TOKEN_TYPE_TEXT = 0,
    SOVEREIGN_TOKEN_TYPE_SPECIAL,
    SOVEREIGN_TOKEN_TYPE_CONTROL,
    SOVEREIGN_TOKEN_TYPE_EOS
} SovereignTokenType;

// ============================================================================
// DATA STRUCTURES
// ============================================================================

typedef struct {
    int32_t token;
    float probability;
    SovereignTokenType type;
    char text[256];  // Detokenized text
} SovereignToken;

typedef struct {
    SovereignStreamState state;
    SovereignToken* tokens;
    int n_tokens;
    int capacity;
    float* logits;
    int n_vocab;
    float temperature;
    float top_p;
    int top_k;
    uint64_t start_time;
    uint64_t end_time;
    int tokens_per_second;
    char error_message[512];
} SovereignStreamContext;

// Streaming callback types
typedef void (*SovereignTokenCallback)(const SovereignToken* token, void* user_data);
typedef void (*SovereignProgressCallback)(SovereignStreamState state, float progress, const char* message, void* user_data);
typedef void (*SovereignErrorCallback)(const char* error, void* user_data);

// ============================================================================
// API FUNCTIONS
// ============================================================================

// Stream context management
SOVEREIGN_API SovereignStreamContext* sovereign_stream_create(SovereignModel* model);
SOVEREIGN_API void sovereign_stream_destroy(SovereignStreamContext* ctx);
SOVEREIGN_API void sovereign_stream_reset(SovereignStreamContext* ctx);

// Streaming inference
SOVEREIGN_API SovereignStatus sovereign_stream_inference(
    SovereignStreamContext* ctx,
    const char* prompt,
    int max_tokens,
    SovereignTokenCallback token_callback,
    SovereignProgressCallback progress_callback,
    SovereignErrorCallback error_callback,
    void* user_data
);

// Streaming with KV cache
SOVEREIGN_API SovereignStatus sovereign_stream_inference_cached(
    SovereignStreamContext* ctx,
    const int32_t* tokens,
    int n_tokens,
    int max_new_tokens,
    SovereignTokenCallback token_callback,
    void* user_data
);

// Cancel streaming
SOVEREIGN_API SovereignStatus sovereign_stream_cancel(SovereignStreamContext* ctx);

// Get stream statistics
SOVEREIGN_API int sovereign_stream_get_tokens_per_second(const SovereignStreamContext* ctx);
SOVEREIGN_API uint64_t sovereign_stream_get_elapsed_time(const SovereignStreamContext* ctx);
SOVEREIGN_API const char* sovereign_stream_get_error(const SovereignStreamContext* ctx);

// Batch streaming
SOVEREIGN_API SovereignStatus sovereign_stream_batch(
    SovereignStreamContext* ctx,
    const char** prompts,
    int n_prompts,
    int max_tokens_per_prompt,
    SovereignTokenCallback token_callback,
    void* user_data
);

// Utility functions
SOVEREIGN_API const char* sovereign_stream_state_string(SovereignStreamState state);
SOVEREIGN_API bool sovereign_stream_is_complete(const SovereignStreamContext* ctx);
SOVEREIGN_API bool sovereign_stream_is_error(const SovereignStreamContext* ctx);

#ifdef __cplusplus
}
#endif

#endif // SOVEREIGN_STREAMING_INFERENCE_H