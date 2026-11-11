// ============================================================================
// test_exports_only.cpp - Export Existence Validation
// ============================================================================

#include <cstdio>

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
    printf("Sovereign Phase 7A - Export Existence Validation\n");
    printf("=================================================================\n\n");
    
    // Just verify function pointers are valid
    printf("[1/5] FlashAttentionV2: %p\n", (void*)flash_attention_v2_f32);
    printf("[2/5] FastTokenScan:    %p\n", (void*)fast_token_scan);
    printf("[3/5] SVD_Compress:     %p\n", (void*)svd_compress_f32);
    printf("[4/5] TokenMerge_AVX512: %p\n", (void*)token_merge_avx512);
    printf("[5/5] Q4_0_Q8_0_MatMul: %p\n", (void*)q4_0_q8_0_matmul);
    
    printf("\n=================================================================\n");
    printf("All 5 resurrected kernel exports validated!\n");
    printf("=================================================================\n");
    
    return 0;
}
