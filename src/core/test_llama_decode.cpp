// =============================================================================
// test_llama_decode.cpp
// Simple test for llama_decode_internal functionality
// =============================================================================

#include "llama_decode_internal.h"
#include "sovereign_transformer_forward.h"
#include <cstdio>
#include <cstring>

using namespace Sovereign;

int main() {
    printf("=== llama_decode_internal Test ===\n\n");
    
    // Create minimal model weights (stub)
    ModelWeights model;
    model.n_layers = 4;
    model.n_heads = 4;
    model.n_kv_heads = 2;
    model.head_dim = 64;
    model.hidden_dim = 256;
    model.ffn_dim = 512;
    model.vocab_size = 1000;
    model.seq_len = 512;
    
    printf("Model config:\n");
    printf("  Layers: %d\n", model.n_layers);
    printf("  Heads: %d\n", model.n_heads);
    printf("  Hidden: %d\n", model.hidden_dim);
    printf("  Vocab: %d\n\n", model.vocab_size);
    
    // Initialize KV cache
    KVCache kv_cache;
    if (!kv_cache.Initialize(model.n_layers, model.seq_len, model.n_kv_heads, model.head_dim)) {
        printf("ERROR: Failed to initialize KV cache\n");
        return 1;
    }
    printf("KV cache initialized: %d tokens max\n\n", model.seq_len);
    
    // Create llama_context
    llama_context ctx;
    if (!ctx.init(&model, &kv_cache)) {
        printf("ERROR: Failed to initialize llama_context\n");
        kv_cache.Cleanup();
        return 1;
    }
    printf("llama_context initialized\n\n");
    
    // Test 1: Single token decode
    printf("Test 1: Single token decode\n");
    int32_t token = 42;
    int32_t pos = 0;
    llama_batch batch1 = llama_batch::single(token, pos);
    
    int result = llama_decode_internal(&ctx, batch1);
    printf("  Input token: %d at position %d\n", token, pos);
    printf("  llama_decode_internal result: %d (%s)\n", result, result == 0 ? "OK" : "ERROR");
    
    if (result == 0) {
        float* logits = llama_get_logits(&ctx);
        if (logits) {
            // Find max logit
            float max_logit = logits[0];
            int max_idx = 0;
            for (int i = 1; i < model.vocab_size; i++) {
                if (logits[i] > max_logit) {
                    max_logit = logits[i];
                    max_idx = i;
                }
            }
            printf("  Output: max logit at token %d (value: %.4f)\n", max_idx, max_logit);
        }
    }
    printf("\n");
    
    // Test 2: Batch decode (3 tokens)
    printf("Test 2: Batch decode (3 tokens)\n");
    int32_t tokens[] = {10, 20, 30};
    int32_t positions[] = {1, 2, 3};
    llama_batch batch2 = llama_batch::init(3, tokens, positions);
    
    result = llama_decode_internal(&ctx, batch2);
    printf("  Input tokens: [%d, %d, %d] at positions [%d, %d, %d]\n", 
           tokens[0], tokens[1], tokens[2], positions[0], positions[1], positions[2]);
    printf("  llama_decode_internal result: %d (%s)\n", result, result == 0 ? "OK" : "ERROR");
    printf("  Sequence position after: %d\n\n", ctx.seq_pos);
    
    // Test 3: Sampling
    printf("Test 3: Token sampling\n");
    int32_t sampled = llama_sample_token(&ctx, 0.8f, 0.95f, 40);
    printf("  Sampled token (temp=0.8, top_p=0.95, top_k=40): %d\n\n", sampled);
    
    // Test 4: KV cache operations
    printf("Test 4: KV cache operations\n");
    printf("  Tokens in KV cache: %d\n", llama_get_kv_cache_token_count(&ctx));
    
    llama_kv_cache_clear(&ctx);
    printf("  After clear: %d tokens\n", llama_get_kv_cache_token_count(&ctx));
    printf("  Context seq_pos after clear: %d\n\n", ctx.seq_pos);
    
    // Test 5: Error handling
    printf("Test 5: Error handling\n");
    llama_context bad_ctx;
    memset(&bad_ctx, 0, sizeof(bad_ctx));
    
    result = llama_decode_internal(&bad_ctx, batch1);
    printf("  Uninitialized context: result=%d (expected -1)\n", result);
    
    llama_batch empty_batch = {};
    result = llama_decode_internal(&ctx, empty_batch);
    printf("  Empty batch: result=%d (expected -3)\n", result);
    printf("\n");
    
    // Cleanup
    ctx.free();
    kv_cache.Cleanup();
    
    printf("=== All tests completed ===\n");
    return 0;
}
