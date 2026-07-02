// =============================================================================
// llama_decode_internal.h
// Core transformer decode API following llama.cpp patterns
// =============================================================================

#ifndef LLAMA_DECODE_INTERNAL_H
#define LLAMA_DECODE_INTERNAL_H

#include <cstdint>
#include <cstddef>

namespace Sovereign {

// Forward declarations
struct ModelWeights;
struct KVCache;
class TransformerForward;

// =============================================================================
// llama_batch - Input batch structure (llama.cpp compatible)
// =============================================================================
struct llama_batch {
    int32_t n_tokens;           // Number of tokens in batch
    int32_t* token;             // Token IDs [n_tokens]
    float* embd;                // Embeddings (if token is NULL) [n_tokens * embd_dim]
    int32_t* pos;               // Positions [n_tokens]
    int32_t* n_seq_id;          // Number of sequence IDs per token [n_tokens]
    int32_t** seq_id;           // Sequence IDs per token [n_tokens][n_seq_id[i]]
    int8_t* logits;             // Whether to output logits [n_tokens]
    
    // Constructor helpers
    static llama_batch init(int32_t n_tokens, int32_t* token, int32_t* pos, 
                             int32_t n_seq_id = 1, int32_t** seq_id = nullptr);
    static llama_batch single(int32_t token_id, int32_t pos, int32_t seq_id = 0);
};

// =============================================================================
// llama_context - Context for inference (llama.cpp compatible)
// =============================================================================
struct llama_context {
    // Model weights reference
    const ModelWeights* model = nullptr;
    
    // KV cache
    KVCache* kv_cache = nullptr;
    
    // Forward pass engine
    TransformerForward* forward = nullptr;
    
    // Output logits buffer [vocab_size]
    float* logits = nullptr;
    
    // Current sequence position
    int32_t seq_pos = 0;
    
    // Configuration
    float temperature = 0.8f;
    float top_p = 0.95f;
    int32_t top_k = 40;
    
    // State
    bool initialized = false;
    
    // Initialize context
    bool init(const ModelWeights* model_, KVCache* kv_cache_);
    void free();
};

// =============================================================================
// Core Decode Function
// =============================================================================

/**
 * @brief Process a batch of tokens through the transformer
 * 
 * @param ctx The llama context
 * @param batch The batch of tokens to process
 * @return 0 on success, negative error code on failure
 * 
 * Error codes:
 *   -1: Invalid context
 *   -2: Model not loaded
 *   -3: Empty batch
 *   -4: No input provided (neither token nor embd)
 *   -5: Embeddings not supported
 *   -6: Invalid token ID
 *   -7: Position out of bounds
 *   -8: Forward pass failed
 */
int llama_decode_internal(llama_context* ctx, const llama_batch& batch);

// =============================================================================
// Logits Access
// =============================================================================

/**
 * @brief Get output logits from last decode
 * @param ctx The llama context
 * @return Pointer to logits array [vocab_size], or nullptr on error
 */
float* llama_get_logits(llama_context* ctx);

/**
 * @brief Get logits for specific batch element
 * @param ctx The llama context
 * @param i Batch element index
 * @return Pointer to logits array [vocab_size] for token i, or nullptr on error
 */
float* llama_get_logits_ith(llama_context* ctx, int32_t i);

// =============================================================================
// Sampling
// =============================================================================

/**
 * @brief Sample next token from logits
 * 
 * @param ctx The llama context
 * @param temperature Temperature for softmax (1.0 = no change, <1.0 = more focused, >1.0 = more random)
 * @param top_p Top-p (nucleus) sampling threshold (1.0 = disabled)
 * @param top_k Top-k sampling threshold (0 = disabled)
 * @return Sampled token ID, or -1 on error
 */
int32_t llama_sample_token(llama_context* ctx, float temperature = 0.8f, 
                            float top_p = 0.95f, int32_t top_k = 40);

// =============================================================================
// KV Cache Management
// =============================================================================

/**
 * @brief Clear KV cache for new sequence
 * @param ctx The llama context
 */
void llama_kv_cache_clear(llama_context* ctx);

/**
 * @brief Remove tokens from KV cache for a sequence
 * @param ctx The llama context
 * @param seq_id Sequence ID
 * @param p0 Start position (inclusive), -1 for all
 * @param p1 End position (exclusive), -1 for all
 */
void llama_kv_cache_seq_rm(llama_context* ctx, int32_t seq_id, int32_t p0, int32_t p1);

/**
 * @brief Copy KV cache from one sequence to another
 * @param ctx The llama context
 * @param seq_id_src Source sequence ID
 * @param seq_id_dst Destination sequence ID
 * @param p0 Start position (inclusive)
 * @param p1 End position (exclusive)
 */
void llama_kv_cache_seq_cp(llama_context* ctx, int32_t seq_id_src, int32_t seq_id_dst, 
                            int32_t p0, int32_t p1);

/**
 * @brief Keep only specified sequence in KV cache
 * @param ctx The llama context
 * @param seq_id Sequence ID to keep
 */
void llama_kv_cache_seq_keep(llama_context* ctx, int32_t seq_id);

/**
 * @brief Add positions to sequence in KV cache
 * @param ctx The llama context
 * @param seq_id Sequence ID
 * @param p0 Start position (inclusive)
 * @param p1 End position (exclusive)
 * @param delta Position delta to add
 */
void llama_kv_cache_seq_add(llama_context* ctx, int32_t seq_id, int32_t p0, int32_t p1, 
                            int32_t delta);

/**
 * @brief Divide positions in KV cache (for RoPE scaling)
 * @param ctx The llama context
 * @param seq_id Sequence ID
 * @param p0 Start position (inclusive)
 * @param p1 End position (exclusive)
 * @param d Divisor
 */
void llama_kv_cache_seq_div(llama_context* ctx, int32_t seq_id, int32_t p0, int32_t p1, 
                            int32_t d);

/**
 * @brief Get number of tokens in KV cache
 * @param ctx The llama context
 * @return Number of tokens in KV cache
 */
int32_t llama_get_kv_cache_token_count(const llama_context* ctx);

/**
 * @brief Get number of used cells in KV cache
 * @param ctx The llama context
 * @return Number of used cells
 */
int32_t llama_get_kv_cache_used_cells(const llama_context* ctx);

/**
 * @brief Defragment KV cache
 * @param ctx The llama context
 */
void llama_kv_cache_defrag(llama_context* ctx);

/**
 * @brief Update KV cache (e.g., for continuous batching)
 * @param ctx The llama context
 */
void llama_kv_cache_update(llama_context* ctx);

// =============================================================================
// Threading
// =============================================================================

/**
 * @brief Set number of threads for inference
 * @param ctx The llama context
 * @param n_threads Number of threads for generation
 * @param n_threads_batch Number of threads for batch processing
 */
void llama_set_n_threads(llama_context* ctx, int32_t n_threads, int32_t n_threads_batch);

/**
 * @brief Get number of threads
 * @param ctx The llama context
 * @return Number of threads
 */
int32_t llama_get_n_threads(llama_context* ctx);

/**
 * @brief Get number of batch threads
 * @param ctx The llama context
 * @return Number of batch threads
 */
int32_t llama_get_n_threads_batch(llama_context* ctx);

// =============================================================================
// Synchronization
// =============================================================================

/**
 * @brief Synchronize GPU operations (if using GPU)
 * @param ctx The llama context
 */
void llama_synchronize(llama_context* ctx);

} // namespace Sovereign

#endif // LLAMA_DECODE_INTERNAL_H
