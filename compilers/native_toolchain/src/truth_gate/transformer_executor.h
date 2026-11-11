/*
 * Truth Gate 003: Transformer Executor
 * 
 * Executes transformer layers using the Sovereign Runtime
 */

#ifndef TRANSFORMER_EXECUTOR_H
#define TRANSFORMER_EXECUTOR_H

#include "gguf_integration.h"
#include "fabric_integration.h"

// Opaque executor handle
struct TransformerExecutor;

// Layer output
struct LayerOutput {
    float* hidden_states;
    int batch_size;
    int seq_len;
    int hidden_dim;
    bool kv_cache_updated;
    float* k_cache;  // Key cache for this layer
    float* v_cache;  // Value cache for this layer
    int cache_len;
};

// Initialize executor
TransformerExecutor* TransformerExecutor_Init(GGUFModel* model, FabricContext* fabric);

// Free executor
void TransformerExecutor_Free(TransformerExecutor* exec);

// Execute single transformer layer
bool TransformerExecutor_ExecuteLayer(TransformerExecutor* exec, int layer_idx,
                                       const float* input, int hidden_dim,
                                       LayerOutput* output);

// Execute full forward pass (all layers)
bool TransformerExecutor_Forward(TransformerExecutor* exec,
                                  const int* input_tokens, int num_tokens,
                                  float* output_logits, int vocab_size);

// Reset KV cache
void TransformerExecutor_ResetCache(TransformerExecutor* exec);

// Get cache length
int TransformerExecutor_GetCacheLen(TransformerExecutor* exec);

#endif // TRANSFORMER_EXECUTOR_H
