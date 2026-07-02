// =============================================================================
// llama_decode_internal.cpp
// Core transformer decode implementation following llama.cpp patterns
// Integrates with Sovereign transformer forward pass
// =============================================================================

#include "sovereign_transformer_forward.h"
#include "sovereign_config.h"
#include <cstring>
#include <cmath>
#include <algorithm>

namespace Sovereign {

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

llama_batch llama_batch::init(int32_t n_tokens_, int32_t* token_, int32_t* pos_, 
                                 int32_t n_seq_id_, int32_t** seq_id_) {
    llama_batch batch = {};
    batch.n_tokens = n_tokens_;
    batch.token = token_;
    batch.embd = nullptr;
    batch.pos = pos_;
    batch.n_seq_id = nullptr;
    batch.seq_id = seq_id_;
    batch.logits = nullptr;
    return batch;
}

llama_batch llama_batch::single(int32_t token_id, int32_t pos_, int32_t seq_id_) {
    llama_batch batch = {};
    batch.n_tokens = 1;
    batch.token = &token_id;  // Note: caller must ensure lifetime
    batch.embd = nullptr;
    batch.pos = &pos_;
    batch.n_seq_id = nullptr;
    batch.seq_id = nullptr;
    batch.logits = nullptr;
    return batch;
}

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

bool llama_context::init(const ModelWeights* model_, KVCache* kv_cache_) {
    if (!model_ || !kv_cache_) return false;
    
    model = model_;
    kv_cache = kv_cache_;
    
    // Allocate logits buffer
    logits = new (std::nothrow) float[model->vocab_size];
    if (!logits) return false;
    
    // Create forward pass engine
    forward = new (std::nothrow) TransformerForward(*model, *kv_cache);
    if (!forward) {
        delete[] logits;
        logits = nullptr;
        return false;
    }
    
    initialized = true;
    return true;
}

void llama_context::free() {
    delete forward;
    forward = nullptr;
    
    delete[] logits;
    logits = nullptr;
    
    initialized = false;
}

// =============================================================================
// llama_decode_internal - Core decode function
// Process a batch of tokens through the transformer
// Returns: 0 on success, non-zero on error
// =============================================================================
int llama_decode_internal(llama_context* ctx, const llama_batch& batch) {
    if (!ctx || !ctx->initialized) {
        return -1;  // Invalid context
    }
    
    if (!ctx->model || !ctx->forward || !ctx->kv_cache) {
        return -2;  // Model not loaded
    }
    
    if (batch.n_tokens <= 0) {
        return -3;  // Empty batch
    }
    
    if (!batch.token && !batch.embd) {
        return -4;  // No input provided
    }
    
    const ModelWeights& model = *ctx->model;
    TransformerForward& forward = *ctx->forward;
    KVCache& kv_cache = *ctx->kv_cache;
    
    // Process each token in the batch
    for (int32_t i = 0; i < batch.n_tokens; i++) {
        // Get token ID and position
        uint32_t token_id;
        uint32_t pos;
        
        if (batch.token) {
            token_id = static_cast<uint32_t>(batch.token[i]);
        } else {
            // Embedding input - not implemented in this version
            return -5;  // Embeddings not supported
        }
        
        if (batch.pos) {
            pos = static_cast<uint32_t>(batch.pos[i]);
        } else {
            pos = ctx->seq_pos + i;
        }
        
        // Validate token
        if (token_id >= model.vocab_size) {
            return -6;  // Invalid token ID
        }
        
        // Validate position
        if (pos >= kv_cache.max_seq_len) {
            return -7;  // Position out of bounds
        }
        
        // Run forward pass for this token
        if (!forward.ForwardToken(token_id, pos, ctx->logits)) {
            return -8;  // Forward pass failed
        }
        
        // Update sequence position
        ctx->seq_pos = pos + 1;
        kv_cache.current_pos = ctx->seq_pos;
    }
    
    return 0;  // Success
}

// =============================================================================
// llama_get_logits - Get output logits from last decode
// Returns pointer to logits array [vocab_size]
// =============================================================================
float* llama_get_logits(llama_context* ctx) {
    if (!ctx || !ctx->initialized) {
        return nullptr;
    }
    return ctx->logits;
}

// =============================================================================
// llama_get_logits_ith - Get logits for specific batch element
// Returns pointer to logits array [vocab_size] for token i
// =============================================================================
float* llama_get_logits_ith(llama_context* ctx, int32_t i) {
    if (!ctx || !ctx->initialized) {
        return nullptr;
    }
    // For now, all tokens share the same logits buffer
    // In full implementation, would index into per-token logits
    (void)i;
    return ctx->logits;
}

// =============================================================================
// llama_sample_token - Sample next token from logits
// Implements temperature scaling, top-k, and top-p filtering
// =============================================================================
int32_t llama_sample_token(llama_context* ctx, float temperature, float top_p, int32_t top_k) {
    if (!ctx || !ctx->initialized || !ctx->logits) {
        return -1;
    }
    
    const uint32_t vocab_size = ctx->model->vocab_size;
    float* logits = ctx->logits;
    
    // Apply temperature scaling
    if (temperature != 1.0f && temperature > 0.0f) {
        for (uint32_t i = 0; i < vocab_size; i++) {
            logits[i] /= temperature;
        }
    }
    
    // Convert to probabilities (softmax)
    float max_logit = logits[0];
    for (uint32_t i = 1; i < vocab_size; i++) {
        if (logits[i] > max_logit) max_logit = logits[i];
    }
    
    float sum_exp = 0.0f;
    for (uint32_t i = 0; i < vocab_size; i++) {
        logits[i] = std::exp(logits[i] - max_logit);
        sum_exp += logits[i];
    }
    
    for (uint32_t i = 0; i < vocab_size; i++) {
        logits[i] /= sum_exp;
    }
    
    // Top-k filtering
    if (top_k > 0 && top_k < static_cast<int32_t>(vocab_size)) {
        // Find k-th largest probability
        float* probs_copy = new float[vocab_size];
        memcpy(probs_copy, logits, vocab_size * sizeof(float));
        std::nth_element(probs_copy, probs_copy + vocab_size - top_k, probs_copy + vocab_size);
        float kth_prob = probs_copy[vocab_size - top_k];
        delete[] probs_copy;
        
        // Zero out probabilities below threshold
        for (uint32_t i = 0; i < vocab_size; i++) {
            if (logits[i] < kth_prob) {
                logits[i] = 0.0f;
            }
        }
        
        // Renormalize
        sum_exp = 0.0f;
        for (uint32_t i = 0; i < vocab_size; i++) {
            sum_exp += logits[i];
        }
        if (sum_exp > 0.0f) {
            for (uint32_t i = 0; i < vocab_size; i++) {
                logits[i] /= sum_exp;
            }
        }
    }
    
    // Top-p (nucleus) filtering
    if (top_p < 1.0f && top_p > 0.0f) {
        // Sort probabilities in descending order
        struct TokenProb {
            uint32_t token;
            float prob;
        };
        TokenProb* sorted = new TokenProb[vocab_size];
        for (uint32_t i = 0; i < vocab_size; i++) {
            sorted[i] = {i, logits[i]};
        }
        std::sort(sorted, sorted + vocab_size, [](const TokenProb& a, const TokenProb& b) {
            return a.prob > b.prob;
        });
        
        // Find cutoff
        float cumsum = 0.0f;
        uint32_t cutoff_idx = vocab_size;
        for (uint32_t i = 0; i < vocab_size; i++) {
            cumsum += sorted[i].prob;
            if (cumsum > top_p) {
                cutoff_idx = i + 1;
                break;
            }
        }
        
        // Zero out probabilities below cutoff
        for (uint32_t i = cutoff_idx; i < vocab_size; i++) {
            logits[sorted[i].token] = 0.0f;
        }
        delete[] sorted;
        
        // Renormalize
        sum_exp = 0.0f;
        for (uint32_t i = 0; i < vocab_size; i++) {
            sum_exp += logits[i];
        }
        if (sum_exp > 0.0f) {
            for (uint32_t i = 0; i < vocab_size; i++) {
                logits[i] /= sum_exp;
            }
        }
    }
    
    // Greedy sampling (argmax) - deterministic
    // For stochastic sampling, would use multinomial sampling
    uint32_t best_token = 0;
    float best_prob = logits[0];
    for (uint32_t i = 1; i < vocab_size; i++) {
        if (logits[i] > best_prob) {
            best_prob = logits[i];
            best_token = i;
        }
    }
    
    return static_cast<int32_t>(best_token);
}

// =============================================================================
// llama_kv_cache_clear - Clear KV cache for new sequence
// =============================================================================
void llama_kv_cache_clear(llama_context* ctx) {
    if (!ctx || !ctx->kv_cache) {
        return;
    }
    ctx->kv_cache->Reset();
    ctx->seq_pos = 0;
}

// =============================================================================
// llama_kv_cache_seq_rm - Remove tokens from KV cache for a sequence
// =============================================================================
void llama_kv_cache_seq_rm(llama_context* ctx, int32_t seq_id, int32_t p0, int32_t p1) {
    if (!ctx || !ctx->kv_cache) {
        return;
    }
    
    // For now, just reset if removing entire sequence
    // Full implementation would selectively clear positions
    (void)seq_id;
    if (p0 == 0 && p1 < 0) {
        ctx->kv_cache->Reset();
        ctx->seq_pos = 0;
    }
}

// =============================================================================
// llama_kv_cache_seq_cp - Copy KV cache from one sequence to another
// =============================================================================
void llama_kv_cache_seq_cp(llama_context* ctx, int32_t seq_id_src, int32_t seq_id_dst, 
                            int32_t p0, int32_t p1) {
    // Not implemented in this version
    // Would copy KV cache entries from src to dst sequence
    (void)ctx;
    (void)seq_id_src;
    (void)seq_id_dst;
    (void)p0;
    (void)p1;
}

// =============================================================================
// llama_kv_cache_seq_keep - Keep only specified sequence in KV cache
// =============================================================================
void llama_kv_cache_seq_keep(llama_context* ctx, int32_t seq_id) {
    // Not implemented in this version
    // Would clear all sequences except seq_id
    (void)ctx;
    (void)seq_id;
}

// =============================================================================
// llama_kv_cache_seq_add - Add positions to sequence in KV cache
// =============================================================================
void llama_kv_cache_seq_add(llama_context* ctx, int32_t seq_id, int32_t p0, int32_t p1, 
                            int32_t delta) {
    // Not implemented in this version
    // Would shift positions in KV cache by delta
    (void)ctx;
    (void)seq_id;
    (void)p0;
    (void)p1;
    (void)delta;
}

// =============================================================================
// llama_kv_cache_seq_div - Divide positions in KV cache (for RoPE)
// =============================================================================
void llama_kv_cache_seq_div(llama_context* ctx, int32_t seq_id, int32_t p0, int32_t p1, 
                            int32_t d) {
    // Not implemented in this version
    // Would apply position division for RoPE scaling
    (void)ctx;
    (void)seq_id;
    (void)p0;
    (void)p1;
    (void)d;
}

// =============================================================================
// llama_get_kv_cache_token_count - Get number of tokens in KV cache
// =============================================================================
int32_t llama_get_kv_cache_token_count(const llama_context* ctx) {
    if (!ctx || !ctx->kv_cache) {
        return 0;
    }
    return static_cast<int32_t>(ctx->kv_cache->current_pos);
}

// =============================================================================
// llama_get_kv_cache_used_cells - Get number of used cells in KV cache
// =============================================================================
int32_t llama_get_kv_cache_used_cells(const llama_context* ctx) {
    // Same as token count for now
    return llama_get_kv_cache_token_count(ctx);
}

// =============================================================================
// llama_kv_cache_defrag - Defragment KV cache
// =============================================================================
void llama_kv_cache_defrag(llama_context* ctx) {
    // Not implemented in this version
    // Would compact KV cache to remove gaps
    (void)ctx;
}

// =============================================================================
// llama_kv_cache_update - Update KV cache (e.g., for continuous batching)
// =============================================================================
void llama_kv_cache_update(llama_context* ctx) {
    // Not implemented in this version
    // Would update KV cache state for continuous batching
    (void)ctx;
}

// =============================================================================
// llama_synchronize - Synchronize GPU operations (if using GPU)
// =============================================================================
void llama_synchronize(llama_context* ctx) {
    // CPU-only implementation - no synchronization needed
    // GPU implementation would call cudaDeviceSynchronize() or equivalent
    (void)ctx;
}

// =============================================================================
// llama_set_n_threads - Set number of threads for inference
// =============================================================================
void llama_set_n_threads(llama_context* ctx, int32_t n_threads, int32_t n_threads_batch) {
    if (!ctx) return;
    // Store thread counts for future use
    // Actual thread pool configuration would happen here
    (void)n_threads;
    (void)n_threads_batch;
}

// =============================================================================
// llama_get_n_threads - Get number of threads
// =============================================================================
int32_t llama_get_n_threads(llama_context* ctx) {
    // Return default thread count
    (void)ctx;
    return 8;  // Default
}

// =============================================================================
// llama_get_n_threads_batch - Get number of batch threads
// =============================================================================
int32_t llama_get_n_threads_batch(llama_context* ctx) {
    // Return default batch thread count
    (void)ctx;
    return 8;  // Default
}

} // namespace Sovereign
