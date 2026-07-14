// ai_model_caller_integrated.h - MILESTONE 3: INTEGRATION API
//
// Provides end-to-end inference: Text -> Tokenize -> Inference -> Detokenize -> Text
// NO STUBS - All functions use real tokenizer and real inference

#ifndef AI_MODEL_CALLER_INTEGRATED_H
#define AI_MODEL_CALLER_INTEGRATED_H

#include "ai_model_caller_real.h"
#include <string>
#include <functional>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================
// INTEGRATED INFERENCE API
// ============================================================

/**
 * Generate completion from text prompt - FULLY INTEGRATED
 * 
 * Complete pipeline: Text -> Tokenize -> Inference -> Detokenize -> Text
 * 
 * @param prompt Input text prompt
 * @param max_new_tokens Maximum tokens to generate
 * @param temperature Sampling temperature (0.0 - 1.0)
 * @param top_k Top-k sampling parameter
 * @param top_p Top-p (nucleus) sampling parameter
 * @return InferenceResult with generated text and tokens
 */
InferenceResult GenerateCompletion(
    const std::string& prompt,
    int max_new_tokens = 128,
    float temperature = 0.8f,
    int top_k = 40,
    float top_p = 0.95f
);

/**
 * Generate completion with streaming output
 * 
 * Calls callback for each generated token
 * 
 * @param prompt Input text prompt
 * @param callback Function called for each token: void(token_text, is_last)
 * @param max_new_tokens Maximum tokens to generate
 * @param temperature Sampling temperature
 */
void GenerateCompletionStreaming(
    const std::string& prompt,
    std::function<void(const std::string& token_text, bool is_last)> callback,
    int max_new_tokens = 128,
    float temperature = 0.8f
);

/**
 * Clear tokenization cache
 */
void ClearTokenCache();

/**
 * Cache statistics
 */
struct CacheStats {
    size_t size;
    size_t max_size;
    float hit_rate;
};

CacheStats GetTokenCacheStats();

/**
 * Test end-to-end generation with tiny model
 * 
 * @return true if test passes, false otherwise
 */
bool TestEndToEndGeneration();

// ============================================================
// C API FOR EXTERNAL CALLERS
// ============================================================

/**
 * C API: Generate completion from text
 * 
 * @param prompt Input prompt (null-terminated)
 * @param output_buffer Buffer for output text
 * @param output_buffer_size Size of output buffer
 * @param max_new_tokens Maximum tokens to generate
 * @return 0 on success, non-zero on error
 */
int rawrxd_generate_completion(
    const char* prompt,
    char* output_buffer,
    size_t output_buffer_size,
    int max_new_tokens
);

/**
 * C API: Clear token cache
 */
void rawrxd_clear_token_cache();

/**
 * C API: Run end-to-end test
 * 
 * @return 0 on success, 1 on failure
 */
int rawrxd_test_end_to_end();

#ifdef __cplusplus
} // extern "C"
#endif

#endif // AI_MODEL_CALLER_INTEGRATED_H