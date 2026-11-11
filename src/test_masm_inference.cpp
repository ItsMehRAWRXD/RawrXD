// ============================================================================
// test_masm_inference.cpp
// Test harness for pure MASM inference
// ============================================================================

#include "masm/rawrxd_masm_bridge.h"
#include "gguf_masm_weight_bridge.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <windows.h>

// Simple test of MASM kernels
void TestMathKernels() {
    printf("=== Testing MASM Math Kernels ===\n");
    
    // Test dot product
    float a[8] = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f, 7.0f, 8.0f};
    float b[8] = {1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f};
    
    float result = rawrxd_dot_f32(a, b, 8);
    printf("Dot product: %.2f (expected: 36.00)\n", result);
    
    // Test RMS norm
    float in[8] = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f, 7.0f, 8.0f};
    float out[8];
    float weight[8] = {1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f};
    
    rawrxd_rms_norm_f32(out, in, weight, 8, 1e-6f);
    printf("RMS norm first element: %.4f\n", out[0]);
    
    printf("Math kernels test complete\n\n");
}

// Test KV cache
void TestKVCache() {
    printf("=== Testing KV Cache ===\n");
    
    RawrXDInferenceCtx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.n_layer = 4;
    ctx.n_ctx = 512;
    ctx.n_embd = 256;
    
    int result = rawrxd_kv_cache_alloc(&ctx, 4, 512, 256);
    if (result == 0) {
        printf("KV cache allocated: K=%p, V=%p\n", ctx.kv_cache_k, ctx.kv_cache_v);
        
        // Write test data
        ctx.kv_cache_k[0] = 1.0f;
        ctx.kv_cache_v[0] = 2.0f;
        printf("Test write: K[0]=%.2f, V[0]=%.2f\n", ctx.kv_cache_k[0], ctx.kv_cache_v[0]);
        
        // Reset
        rawrxd_kv_cache_reset(&ctx);
        printf("After reset: K[0]=%.2f, V[0]=%.2f\n", ctx.kv_cache_k[0], ctx.kv_cache_v[0]);
        
        // Free
        rawrxd_kv_cache_free(&ctx);
        printf("KV cache freed\n");
    } else {
        printf("KV cache allocation failed\n");
    }
    
    printf("KV cache test complete\n\n");
}

// Test forward pass
void TestForwardPass() {
    printf("=== Testing Forward Pass ===\n");
    
    RawrXDInferenceCtx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.n_vocab = 1000;
    ctx.n_embd = 256;
    ctx.n_head = 8;
    ctx.n_layer = 4;
    ctx.n_ff = 1024;
    ctx.n_ctx = 512;
    
    // Allocate KV cache
    rawrxd_kv_cache_alloc(&ctx, 4, 512, 256);
    
    // Allocate logits
    float* logits = (float*)malloc(ctx.n_vocab * sizeof(float));
    
    // Run forward pass
    clock_t start = clock();
    rawrxd_forward_token(logits, 42, &ctx);
    clock_t end = clock();
    
    double ms = ((double)(end - start)) / CLOCKS_PER_SEC * 1000.0;
    printf("Forward pass took %.3f ms\n", ms);
    
    // Check output
    printf("Logits[0..4]: %.4f %.4f %.4f %.4f %.4f\n",
           logits[0], logits[1], logits[2], logits[3], logits[4]);
    
    // Sample
    int next_token = rawrxd_sample_top_k(logits, ctx.n_vocab, 40, 0.8f);
    printf("Sampled token: %d\n", next_token);
    
    // Cleanup
    free(logits);
    rawrxd_kv_cache_free(&ctx);
    
    printf("Forward pass test complete\n\n");
}

// Test GGUF weight loading
void TestGGUFLoading(const wchar_t* ggufPath) {
    printf("=== Testing GGUF Weight Loading ===\n");
    
    RawrXDInferenceCtx ctx;
    memset(&ctx, 0, sizeof(ctx));
    
    // Initialize from GGUF
    if (MASM_InitContextFromGGUF(ggufPath, &ctx)) {
        printf("Context initialized from GGUF\n");
        printf("  n_vocab: %d\n", ctx.n_vocab);
        printf("  n_embd: %d\n", ctx.n_embd);
        printf("  n_head: %d\n", ctx.n_head);
        printf("  n_layer: %d\n", ctx.n_layer);
        
        // Load weights
        if (MASM_LoadGGUFWeights(ggufPath, &ctx)) {
            printf("Weights loaded successfully\n");
            
            // Test inference with real weights
            float* logits = (float*)malloc(ctx.n_vocab * sizeof(float));
            rawrxd_forward_token(logits, 1, &ctx);
            
            int next_token = rawrxd_sample_top_k(logits, ctx.n_vocab, 40, 0.8f);
            printf("Generated token: %d\n", next_token);
            
            free(logits);
        } else {
            printf("Failed to load weights\n");
        }
        
        // Cleanup
        MASM_FreeWeights(&ctx);
        rawrxd_kv_cache_free(&ctx);
    } else {
        printf("Failed to initialize from GGUF\n");
    }
    
    printf("GGUF loading test complete\n\n");
}

int wmain(int argc, wchar_t* argv[]) {
    printf("RawrXD Pure MASM Inference Test Harness\n");
    printf("========================================\n\n");
    
    // Run basic tests
    TestMathKernels();
    TestKVCache();
    TestForwardPass();
    
    // Test with GGUF if provided
    if (argc > 1) {
        TestGGUFLoading(argv[1]);
    } else {
        printf("Usage: test_masm_inference.exe <model.gguf>\n");
    }
    
    printf("All tests complete!\n");
    return 0;
}
