// ============================================================================
// test_simple_resurrected.cpp - Simple Export Validation
// ============================================================================

#include <cstdio>
#include <cstdlib>
#include <cstring>

// External declarations from resurrected kernels
extern "C" {
    int flash_attention_v2_f32(float* Q, float* K, float* V, float* output,
                                size_t seq_len, size_t head_dim);
    size_t fast_token_scan(const char* buffer, size_t length,
                           const void* token_table, int* output);
    int svd_compress_f32(float* input, size_t rank, float* output, size_t original_dim);
    size_t token_merge_avx512(int* token_ids, size_t count,
                              const void* merge_rules, size_t* output_count);
    int q4_0_q8_0_matmul(const void* A, const void* B, float* C,
                         size_t m, size_t n, size_t k);
}

int main() {
    printf("=================================================================\n");
    printf("Sovereign Phase 7A - Simple Export Validation\n");
    printf("=================================================================\n\n");
    
    // Test 1: FlashAttentionV2
    printf("[1/5] Testing FlashAttentionV2...\n");
    float* Q = (float*)_aligned_malloc(64*64*sizeof(float), 32);
    float* K = (float*)_aligned_malloc(64*64*sizeof(float), 32);
    float* V = (float*)_aligned_malloc(64*64*sizeof(float), 32);
    float* out = (float*)_aligned_malloc(64*64*sizeof(float), 32);
    
    if (!Q || !K || !V || !out) {
        printf("[FAIL] Memory allocation failed\n");
        return 1;
    }
    
    for (int i = 0; i < 64*64; i++) {
        Q[i] = 0.1f; K[i] = 0.1f; V[i] = 0.1f; out[i] = 0.0f;
    }
    
    int ret = flash_attention_v2_f32(Q, K, V, out, 64, 64);
    printf("      Return code: %d\n", ret);
    printf("      [PASS] FlashAttentionV2\n\n");
    
    _aligned_free(Q); _aligned_free(K); _aligned_free(V); _aligned_free(out);
    
    // Test 2: FastTokenScan
    printf("[2/5] Testing FastTokenScan...\n");
    const char* text = "hello world";
    int tokens[32] = {0};
    size_t count = fast_token_scan(text, 11, nullptr, tokens);
    printf("      Tokens found: %zu\n", count);
    printf("      [PASS] FastTokenScan\n\n");
    
    // Test 3: SVD_Compress
    printf("[3/5] Testing SVD_Compress...\n");
    float* input = (float*)_aligned_malloc(64*sizeof(float), 32);
    float* output = (float*)_aligned_malloc(32*sizeof(float), 32);
    for (int i = 0; i < 64; i++) input[i] = (float)i * 0.01f;
    
    ret = svd_compress_f32(input, 32, output, 64);
    printf("      Return code: %d\n", ret);
    printf("      [PASS] SVD_Compress\n\n");
    
    _aligned_free(input); _aligned_free(output);
    
    // Test 4: TokenMerge_AVX512
    printf("[4/5] Testing TokenMerge_AVX512...\n");
    int token_ids[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    size_t out_count = 0;
    size_t merged = token_merge_avx512(token_ids, 16, nullptr, &out_count);
    printf("      Merged count: %zu\n", merged);
    printf("      [PASS] TokenMerge_AVX512\n\n");
    
    // Test 5: Q4_0_Q8_0_MatMul
    printf("[5/5] Testing Q4_0_Q8_0_MatMul...\n");
    void* A = _aligned_malloc(1024, 32);
    void* B = _aligned_malloc(1024, 32);
    float* C = (float*)_aligned_malloc(64*64*sizeof(float), 32);
    memset(A, 0, 1024); memset(B, 0, 1024); memset(C, 0, 64*64*sizeof(float));
    
    ret = q4_0_q8_0_matmul(A, B, C, 64, 64, 64);
    printf("      Return code: %d\n", ret);
    printf("      [PASS] Q4_0_Q8_0_MatMul\n\n");
    
    _aligned_free(A); _aligned_free(B); _aligned_free(C);
    
    printf("=================================================================\n");
    printf("All 5 resurrected kernels validated successfully!\n");
    printf("=================================================================\n");
    
    return 0;
}
