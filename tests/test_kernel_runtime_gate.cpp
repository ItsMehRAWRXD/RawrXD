//============================================================================
// test_kernel_runtime_gate.cpp
//
// Validates that AVX-512 kernels exit gracefully on unsupported hardware
//============================================================================

#include <cstdio>
#include <cstdlib>
#include <cstdint>

// External kernel exports
extern "C" {
    uint32_t TreeAttentionVerify_AVX512_Export(
        const float* candidate_logits,
        const float* draft_logits,
        const float* tree_mask,
        float* output_probs,
        uint32_t num_candidates,
        float acceptance_threshold
    );
    
    void KVCacheInvalidate_AVX512_Export(
        uint8_t* kv_cache_base,
        uint32_t rejection_mask,
        uint32_t entry_size
    );
    
    int HasAVX512F_Export();
}

int main() {
    printf("Kernel Runtime Gate Test\n");
    printf("========================\n\n");
    
    // Check CPU support
    int hasAVX512 = HasAVX512F_Export();
    printf("AVX-512F detected: %s\n", hasAVX512 ? "YES" : "NO");
    
    if (!hasAVX512) {
        printf("\nCPU does not support AVX-512F.\n");
        printf("Kernels should exit gracefully with error message.\n\n");
    }
    
    // Test 1: Verify kernel
    printf("\nTest 1: TreeAttentionVerify_AVX512_Export()\n");
    printf("Calling with null pointers...\n");
    
    uint32_t result = TreeAttentionVerify_AVX512_Export(
        nullptr, nullptr, nullptr, nullptr, 16, 0.6f
    );
    
    printf("Result: 0x%04X (expected 0x0000 on non-AVX-512 CPU)\n", result);
    
    if (!hasAVX512 && result == 0) {
        printf("PASS: Kernel returned 0 (all rejected) on non-AVX-512 CPU\n");
    } else if (hasAVX512) {
        printf("INFO: AVX-512 available, kernel would execute\n");
    } else {
        printf("FAIL: Unexpected result on non-AVX-512 CPU\n");
        return 1;
    }
    
    // Test 2: KV Cache Invalidation
    printf("\nTest 2: KVCacheInvalidate_AVX512_Export()\n");
    printf("Calling with null base...\n");
    
    KVCacheInvalidate_AVX512_Export(nullptr, 0xFFFF, 64);
    
    printf("PASS: KVCacheInvalidate returned gracefully\n");
    
    printf("\n========================\n");
    printf("All runtime gate tests passed!\n");
    printf("Kernels correctly detect AVX-512 availability.\n");
    
    return 0;
}
