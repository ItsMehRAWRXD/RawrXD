// ============================================================================
// RawrXD Phase 7D: Real Model Integration - GGUF Checkpoint Hooks
// ============================================================================
// Integration layer between GGUF loader and hash chain verification
// Inserts RAWRXD_CHECKPOINT_* calls into the live inference pipeline
// ============================================================================

#pragma once

#include <cstdint>
#include <cstddef>
#include "../core/hash_chain.hpp"

// Forward declaration for GGUF types
struct gguf_tensor;
struct gguf_context;

namespace RawrXD {
namespace Integration {

// ============================================================================
// GGUF Tensor Hash Context
// ============================================================================

struct GGUFCheckpointContext {
    Core::InferenceCheckpointManager* checkpoint_mgr = nullptr;
    uint64_t model_hash = 0;
    uint64_t prompt_hash = 0;
    uint32_t current_layer = 0;
    uint32_t current_token_pos = 0;
    bool enabled = false;
    
    // Statistics
    uint32_t tensors_hashed = 0;
    uint64_t bytes_hashed = 0;
    double hash_time_ms = 0.0;
};

// ============================================================================
// Checkpoint Macros for Hot Path Integration
// ============================================================================

// These macros are designed to be inserted into transformer inference code
// They compile away when RAWRXD_ENABLE_CHECKPOINTS is not defined

#ifdef RAWRXD_ENABLE_CHECKPOINTS
    #define RAWRXD_CHECKPOINT_GGUF_HEADER(ctx, header_data, header_size) \
        do { if (ctx && ctx->enabled && ctx->checkpoint_mgr) { \
            ctx->checkpoint_mgr->CheckpointRaw(HashStage::GGUF_HEADER, header_data, header_size, 0, 0, "gguf_header"); \
        } } while(0)

    #define RAWRXD_CHECKPOINT_TENSOR_RAW(ctx, tensor_data, tensor_size, layer, name) \
        do { if (ctx && ctx->enabled && ctx->checkpoint_mgr) { \
            ctx->checkpoint_mgr->CheckpointRaw(HashStage::TENSOR_RAW, tensor_data, tensor_size, layer, 0, name); \
            ctx->tensors_hashed++; ctx->bytes_hashed += tensor_size; \
        } } while(0)

    #define RAWRXD_CHECKPOINT_EMBEDDING(ctx, embeddings, token_count, hidden_dim) \
        do { if (ctx && ctx->enabled && ctx->checkpoint_mgr) { \
            ctx->checkpoint_mgr->CheckpointEmbedding(embeddings, token_count, hidden_dim); \
        } } while(0)

    #define RAWRXD_CHECKPOINT_RMSNORM(ctx, output, seq_len, hidden_dim, layer) \
        do { if (ctx && ctx->enabled && ctx->checkpoint_mgr) { \
            ctx->checkpoint_mgr->CheckpointRMSNorm(output, seq_len, hidden_dim, layer); \
            ctx->current_layer = layer; \
        } } while(0)

    #define RAWRXD_CHECKPOINT_ATTENTION(ctx, attn_out, seq_len, hidden_dim, layer) \
        do { if (ctx && ctx->enabled && ctx->checkpoint_mgr) { \
            ctx->checkpoint_mgr->CheckpointAttentionOutput(attn_out, seq_len, hidden_dim, layer); \
        } } while(0)

    #define RAWRXD_CHECKPOINT_KV_CACHE(ctx, k_cache, v_cache, seq_len, head_dim, layer) \
        do { if (ctx && ctx->enabled && ctx->checkpoint_mgr) { \
            ctx->checkpoint_mgr->CheckpointKVAppend(k_cache, v_cache, seq_len, head_dim, layer); \
        } } while(0)

    #define RAWRXD_CHECKPOINT_FFN(ctx, ffn_out, seq_len, hidden_dim, layer) \
        do { if (ctx && ctx->enabled && ctx->checkpoint_mgr) { \
            ctx->checkpoint_mgr->CheckpointPostMLP(ffn_out, seq_len, hidden_dim, layer); \
        } } while(0)

    #define RAWRXD_CHECKPOINT_LOGITS(ctx, logits, vocab_size, token_pos) \
        do { if (ctx && ctx->enabled && ctx->checkpoint_mgr) { \
            ctx->checkpoint_mgr->CheckpointLogits(logits, vocab_size, token_pos); \
            ctx->current_token_pos = token_pos; \
        } } while(0)

    #define RAWRXD_CHECKPOINT_SAMPLER(ctx, token, temp, top_p, top_k, pos) \
        do { if (ctx && ctx->enabled && ctx->checkpoint_mgr) { \
            ctx->checkpoint_mgr->CheckpointSampler(token, temp, top_p, top_k, pos); \
        } } while(0)
#else
    // No-op when checkpoints disabled
    #define RAWRXD_CHECKPOINT_GGUF_HEADER(ctx, header_data, header_size) ((void)0)
    #define RAWRXD_CHECKPOINT_TENSOR_RAW(ctx, tensor_data, tensor_size, layer, name) ((void)0)
    #define RAWRXD_CHECKPOINT_EMBEDDING(ctx, embeddings, token_count, hidden_dim) ((void)0)
    #define RAWRXD_CHECKPOINT_RMSNORM(ctx, output, seq_len, hidden_dim, layer) ((void)0)
    #define RAWRXD_CHECKPOINT_ATTENTION(ctx, attn_out, seq_len, hidden_dim, layer) ((void)0)
    #define RAWRXD_CHECKPOINT_KV_CACHE(ctx, k_cache, v_cache, seq_len, head_dim, layer) ((void)0)
    #define RAWRXD_CHECKPOINT_FFN(ctx, ffn_out, seq_len, hidden_dim, layer) ((void)0)
    #define RAWRXD_CHECKPOINT_LOGITS(ctx, logits, vocab_size, token_pos) ((void)0)
    #define RAWRXD_CHECKPOINT_SAMPLER(ctx, token, temp, top_p, top_k, pos) ((void)0)
#endif

// ============================================================================
// Integration Functions
// ============================================================================

// Initialize checkpoint context for a GGUF model
bool GGUFCheckpoint_Init(GGUFCheckpointContext* ctx, 
                         const char* model_path,
                         const char* model_version,
                         const char* fabric_policy);

// Hash GGUF file header and metadata
uint64_t GGUFCheckpoint_HashFile(const char* gguf_path);

// Hash raw tensor data from GGUF loader
uint64_t GGUFCheckpoint_HashTensor(const void* tensor_data, size_t tensor_size, 
                                    uint32_t ggml_type, uint32_t layer_index);

// Export proof after inference completes
bool GGUFCheckpoint_ExportProof(GGUFCheckpointContext* ctx, const char* output_path);

// Get checkpoint statistics
void GGUFCheckpoint_GetStats(GGUFCheckpointContext* ctx, 
                              uint32_t* out_tensors,
                              uint64_t* out_bytes,
                              double* out_time_ms);

// ============================================================================
// Transformer Layer Integration Helpers
// ============================================================================

// Call at start of each transformer layer
inline void GGUFCheckpoint_BeginLayer(GGUFCheckpointContext* ctx, uint32_t layer) {
    if (ctx) ctx->current_layer = layer;
}

// Call at end of each transformer layer
inline void GGUFCheckpoint_EndLayer(GGUFCheckpointContext* ctx) {
    // Layer complete - could trigger async flush here
}

// Call at start of token generation
inline void GGUFCheckpoint_BeginToken(GGUFCheckpointContext* ctx, uint32_t pos) {
    if (ctx) ctx->current_token_pos = pos;
}

} // namespace Integration
} // namespace RawrXD
