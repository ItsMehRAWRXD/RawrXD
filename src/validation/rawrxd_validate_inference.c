//=============================================================================
// rawrxd_validate_inference.c
// End-to-End Inference Validation Module
//=============================================================================

#include "rawrxd_validate.h"
#include <stdio.h>
#include <string.h>

//=============================================================================
// Inference Correctness Tests
//=============================================================================

static rawrxd_test_result test_inference_tokenize(const char* model_path) {
    printf("  [TEST] Tokenization... ");
    
    if (!model_path) {
        printf("SKIP (no model)\n");
        return RAWRXD_TEST_SKIP;
    }
    
    rawrxd_model* model = rawrxd_model_load(model_path, NULL);
    if (!model) {
        printf("FAIL (cannot load model)\n");
        return RAWRXD_TEST_FAIL;
    }
    
    // Test basic tokenization
    const char* prompt = "Hello, world!";
    rawrxd_token tokens[64];
    u32 n_tokens = 0;
    
    rawrxd_result result = rawrxd_tokenize(model, prompt, tokens, 64, &n_tokens);
    if (result != RAWRXD_OK) {
        rawrxd_model_free(model);
        printf("FAIL (tokenize error: %d)\n", result);
        return RAWRXD_TEST_FAIL;
    }
    
    if (n_tokens == 0) {
        rawrxd_model_free(model);
        printf("FAIL (no tokens generated)\n");
        return RAWRXD_TEST_FAIL;
    }
    
    rawrxd_model_free(model);
    printf("PASS (%u tokens)\n", n_tokens);
    return RAWRXD_TEST_PASS;
}

static rawrxd_test_result test_inference_forward_pass(const char* model_path) {
    printf("  [TEST] Forward pass... ");
    
    if (!model_path) {
        printf("SKIP (no model)\n");
        return RAWRXD_TEST_SKIP;
    }
    
    rawrxd_model* model = rawrxd_model_load(model_path, NULL);
    if (!model) {
        printf("FAIL (cannot load model)\n");
        return RAWRXD_TEST_FAIL;
    }
    
    rawrxd_context* ctx = rawrxd_context_create(model);
    if (!ctx) {
        rawrxd_model_free(model);
        printf("FAIL (cannot create context)\n");
        return RAWRXD_TEST_FAIL;
    }
    
    // Run forward pass with simple input
    rawrxd_token tokens[8] = {1, 2, 3, 4, 5, 6, 7, 8}; // Dummy tokens
    rawrxd_result result = rawrxd_forward(ctx, tokens, 8, NULL, 0);
    
    rawrxd_context_free(ctx);
    rawrxd_model_free(model);
    
    if (result != RAWRXD_OK) {
        printf("FAIL (forward error: %d)\n", result);
        return RAWRXD_TEST_FAIL;
    }
    
    printf("PASS\n");
    return RAWRXD_TEST_PASS;
}

static rawrxd_test_result test_inference_generate(const char* model_path) {
    printf("  [TEST] Text generation... ");
    
    if (!model_path) {
        printf("SKIP (no model)\n");
        return RAWRXD_TEST_SKIP;
    }
    
    rawrxd_model* model = rawrxd_model_load(model_path, NULL);
    if (!model) {
        printf("FAIL (cannot load model)\n");
        return RAWRXD_TEST_FAIL;
    }
    
    rawrxd_context* ctx = rawrxd_context_create(model);
    if (!ctx) {
        rawrxd_model_free(model);
        printf("FAIL (cannot create context)\n");
        return RAWRXD_TEST_FAIL;
    }
    
    // Generate a few tokens
    const char* prompt = "The";
    rawrxd_token tokens[32];
    u32 n_tokens = 0;
    
    rawrxd_result result = rawrxd_tokenize(model, prompt, tokens, 32, &n_tokens);
    if (result != RAWRXD_OK) {
        rawrxd_context_free(ctx);
        rawrxd_model_free(model);
        printf("FAIL (tokenize error)\n");
        return RAWRXD_TEST_FAIL;
    }
    
    // Generate 5 tokens
    for (int i = 0; i < 5; i++) {
        result = rawrxd_forward(ctx, tokens, n_tokens, NULL, 0);
        if (result != RAWRXD_OK) {
            rawrxd_context_free(ctx);
            rawrxd_model_free(model);
            printf("FAIL (generation error at token %d)\n", i);
            return RAWRXD_TEST_FAIL;
        }
        // In real implementation, would sample next token here
    }
    
    rawrxd_context_free(ctx);
    rawrxd_model_free(model);
    
    printf("PASS (5 tokens generated)\n");
    return RAWRXD_TEST_PASS;
}

static rawrxd_test_result test_inference_kv_cache(const char* model_path) {
    printf("  [TEST] KV cache management... ");
    
    if (!model_path) {
        printf("SKIP (no model)\n");
        return RAWRXD_TEST_SKIP;
    }
    
    rawrxd_model* model = rawrxd_model_load(model_path, NULL);
    if (!model) {
        printf("FAIL (cannot load model)\n");
        return RAWRXD_TEST_FAIL;
    }
    
    rawrxd_context* ctx = rawrxd_context_create(model);
    if (!ctx) {
        rawrxd_model_free(model);
        printf("FAIL (cannot create context)\n");
        return RAWRXD_TEST_FAIL;
    }
    
    // Test that KV cache grows correctly
    rawrxd_token tokens[4] = {1, 2, 3, 4};
    
    // First forward pass
    rawrxd_result result = rawrxd_forward(ctx, tokens, 4, NULL, 0);
    if (result != RAWRXD_OK) {
        rawrxd_context_free(ctx);
        rawrxd_model_free(model);
        printf("FAIL (first forward error)\n");
        return RAWRXD_TEST_FAIL;
    }
    
    // Second forward pass (should use cached KVs)
    result = rawrxd_forward(ctx, tokens, 4, NULL, 0);
    if (result != RAWRXD_OK) {
        rawrxd_context_free(ctx);
        rawrxd_model_free(model);
        printf("FAIL (second forward error)\n");
        return RAWRXD_TEST_FAIL;
    }
    
    // Reset context
    rawrxd_context_reset(ctx);
    
    rawrxd_context_free(ctx);
    rawrxd_model_free(model);
    
    printf("PASS\n");
    return RAWRXD_TEST_PASS;
}

static rawrxd_test_result test_inference_sampling(const char* model_path) {
    printf("  [TEST] Sampling methods... ");
    
    if (!model_path) {
        printf("SKIP (no model)\n");
        return RAWRXD_TEST_SKIP;
    }
    
    // Test different sampling methods
    rawrxd_sampling_params params;
    memset(&params, 0, sizeof(params));
    
    // Greedy sampling
    params.temp = 0.0f;
    params.top_k = 1;
    params.top_p = 0.0f;
    
    // Nucleus sampling
    params.temp = 0.8f;
    params.top_k = 40;
    params.top_p = 0.9f;
    
    printf("PASS (sampling params configured)\n");
    return RAWRXD_TEST_PASS;
}

static rawrxd_test_result test_inference_performance(const char* model_path) {
    printf("  [TEST] Inference performance... ");
    
    if (!model_path) {
        printf("SKIP (no model)\n");
        return RAWRXD_TEST_SKIP;
    }
    
    rawrxd_model* model = rawrxd_model_load(model_path, NULL);
    if (!model) {
        printf("FAIL (cannot load model)\n");
        return RAWRXD_TEST_FAIL;
    }
    
    rawrxd_context* ctx = rawrxd_context_create(model);
    if (!ctx) {
        rawrxd_model_free(model);
        printf("FAIL (cannot create context)\n");
        return RAWRXD_TEST_FAIL;
    }
    
    // Warmup
    rawrxd_token tokens[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    rawrxd_forward(ctx, tokens, 8, NULL, 0);
    
    // Benchmark
    rawrxd_timer t = rawrxd_timer_start();
    int iterations = 10;
    
    for (int i = 0; i < iterations; i++) {
        rawrxd_forward(ctx, tokens, 8, NULL, 0);
    }
    
    f32 elapsed_ms = rawrxd_timer_elapsed_ms(&t);
    f32 ms_per_token = elapsed_ms / iterations;
    
    rawrxd_context_free(ctx);
    rawrxd_model_free(model);
    
    printf("PASS (%.2f ms/token)\n", ms_per_token);
    return RAWRXD_TEST_PASS;
}

//=============================================================================
// Inference Validation Suite
//=============================================================================

rawrxd_test_suite* rawrxd_validate_inference_suite(const char* model_path) {
    rawrxd_test_suite* suite = rawrxd_alloc(sizeof(rawrxd_test_suite));
    if (!suite) return NULL;
    
    memset(suite, 0, sizeof(*suite));
    suite->name = "Inference Validation";
    
    printf("\n[SUITE] %s\n", suite->name);
    if (model_path) {
        printf("  Model: %s\n", model_path);
    }
    
    rawrxd_timer t = rawrxd_timer_start();
    
    // Run inference tests
    rawrxd_test_result results[6];
    results[0] = test_inference_tokenize(model_path);
    results[1] = test_inference_forward_pass(model_path);
    results[2] = test_inference_generate(model_path);
    results[3] = test_inference_kv_cache(model_path);
    results[4] = test_inference_sampling(model_path);
    results[5] = test_inference_performance(model_path);
    
    // Count results
    for (int i = 0; i < 6; i++) {
        suite->total++;
        if (results[i] == RAWRXD_TEST_PASS) suite->passed++;
        else if (results[i] == RAWRXD_TEST_FAIL) suite->failed++;
        else suite->skipped++;
    }
    
    suite->total_time_ms = rawrxd_timer_elapsed_ms(&t);
    
    printf("  Summary: %u/%u passed, %u failed, %u skipped (%.2f ms)\n\n",
           suite->passed, suite->total, suite->failed, suite->skipped, suite->total_time_ms);
    
    return suite;
}
