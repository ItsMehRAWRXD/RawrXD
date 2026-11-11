//============================================================================
// speculative_smoke_intrinsics.cpp
//
// VAL-032: Smoke Test Harness for Intrinsics-Based Tree Attention
//
// Validates:
//   - Kernel correctness with deterministic vectors
//   - Mask extraction and propagation
//   - Branchless invalidation logic
//   - Cycle-accurate performance baseline
//============================================================================

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cmath>
#include <immintrin.h>

// External intrinsics kernel exports
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
    
    uint64_t ReadTSC_Export();
    int HasAVX512F_Export();
}

// Align to 64-byte boundary for AVX-512
#ifdef _MSC_VER
    #define ALIGN64 __declspec(align(64))
#else
    #define ALIGN64 __attribute__((aligned(64)))
#endif

// Aligned allocation helper
template<typename T>
T* AlignedAlloc(size_t count, size_t alignment = 64) {
    size_t size = count * sizeof(T);
    void* ptr = nullptr;
    #ifdef _MSC_VER
        ptr = _aligned_malloc(size, alignment);
    #else
        ptr = aligned_alloc(alignment, size);
    #endif
    return static_cast<T*>(ptr);
}

void AlignedFree(void* ptr) {
    #ifdef _MSC_VER
        _aligned_free(ptr);
    #else
        free(ptr);
    #endif
}

struct TestResult {
    const char* name;
    bool passed;
    uint64_t cycles;
    const char* error_msg;
};

//============================================================================
// Test Utilities
//============================================================================

inline uint64_t ReadTSC() {
    _mm_lfence();
    uint64_t tsc = __rdtsc();
    _mm_lfence();
    return tsc;
}

bool IsAligned64(const void* ptr) {
    return (((uintptr_t)ptr) & 0x3F) == 0;
}

bool FloatEquals(float a, float b, float epsilon = 1e-5f) {
    return fabsf(a - b) < epsilon;
}

//============================================================================
// Test Cases
//============================================================================

// Test 1: Basic acceptance (all tokens valid, high confidence)
TestResult Test_AllAccept() {
    TestResult result = {"AllAccept", false, 0, nullptr};
    
    float* candidate_logits = AlignedAlloc<float>(16 * 64);
    float* draft_logits = AlignedAlloc<float>(16 * 64);
    float* tree_mask = AlignedAlloc<float>(64);
    float* output_probs = AlignedAlloc<float>(16);
    
    if (!candidate_logits || !draft_logits || !tree_mask || !output_probs) {
        result.error_msg = "Memory allocation failed";
        AlignedFree(candidate_logits);
        AlignedFree(draft_logits);
        AlignedFree(tree_mask);
        AlignedFree(output_probs);
        return result;
    }
    
    // Initialize with matching logits (high confidence)
    for (int i = 0; i < 16 * 64; i++) {
        candidate_logits[i] = 1.0f;
        draft_logits[i] = 0.5f;
    }
    
    // Tree mask: all valid (0xFFFF), draft probs = 0.5
    memset(tree_mask, 0, 64 * sizeof(float));
    *(uint16_t*)tree_mask = 0xFFFF;  // All 16 valid
    for (int i = 0; i < 16; i++) {
        tree_mask[16 + i] = 0.5f;  // Draft probabilities
    }
    
    // Verify alignment
    if (!IsAligned64(candidate_logits) || !IsAligned64(draft_logits) || 
        !IsAligned64(tree_mask) || !IsAligned64(output_probs)) {
        result.error_msg = "Alignment check failed";
        AlignedFree(candidate_logits);
        AlignedFree(draft_logits);
        AlignedFree(tree_mask);
        AlignedFree(output_probs);
        return result;
    }
    
    // Check AVX-512 support
    if (!HasAVX512F_Export()) {
        result.error_msg = "AVX-512 not supported";
        AlignedFree(candidate_logits);
        AlignedFree(draft_logits);
        AlignedFree(tree_mask);
        AlignedFree(output_probs);
        return result;
    }
    
    // Run kernel with cycle counting
    uint64_t start = ReadTSC();
    uint32_t accept_mask = TreeAttentionVerify_AVX512_Export(
        candidate_logits, draft_logits, tree_mask, 
        output_probs, 16, 0.6f
    );
    uint64_t end = ReadTSC();
    result.cycles = end - start;
    
    // All should be accepted (accept_mask = 0xFFFF)
    if (accept_mask != 0xFFFF) {
        result.error_msg = "Expected all accepted";
        AlignedFree(candidate_logits);
        AlignedFree(draft_logits);
        AlignedFree(tree_mask);
        AlignedFree(output_probs);
        return result;
    }
    
    result.passed = true;
    AlignedFree(candidate_logits);
    AlignedFree(draft_logits);
    AlignedFree(tree_mask);
    AlignedFree(output_probs);
    return result;
}

// Test 2: Full rejection (all tokens below threshold)
TestResult Test_AllReject() {
    TestResult result = {"AllReject", false, 0, nullptr};
    
    ALIGN64 float candidate_logits[16 * 64];
    ALIGN64 float draft_logits[16 * 64];
    ALIGN64 float tree_mask[64];
    ALIGN64 float output_probs[16];
    
    // Candidates with low scores, draft with high scores
    for (int i = 0; i < 16 * 64; i++) {
        candidate_logits[i] = 0.1f;
        draft_logits[i] = 1.0f;
    }
    
    // Tree mask: all valid, high draft probs
    memset(tree_mask, 0, sizeof(tree_mask));
    *(uint16_t*)tree_mask = 0xFFFF;
    for (int i = 0; i < 16; i++) {
        tree_mask[16 + i] = 0.9f;  // High draft probs
    }
    
    uint64_t start = ReadTSC();
    uint32_t accept_mask = TreeAttentionVerify_AVX512_Export(
        candidate_logits, draft_logits, tree_mask,
        output_probs, 16, 0.6f
    );
    uint64_t end = ReadTSC();
    result.cycles = end - start;
    
    // All should be rejected (accept_mask = 0)
    if (accept_mask != 0) {
        result.error_msg = "Expected all rejected";
        return result;
    }
    
    result.passed = true;
    return result;
}

// Test 3: Partial acceptance (mixed results)
TestResult Test_PartialAccept() {
    TestResult result = {"PartialAccept", false, 0, nullptr};
    
    ALIGN64 float candidate_logits[16 * 64];
    ALIGN64 float draft_logits[16 * 64];
    ALIGN64 float tree_mask[64];
    ALIGN64 float output_probs[16];
    
    // First 8 candidates match well, last 8 poorly
    for (int c = 0; c < 8; c++) {
        for (int i = 0; i < 64; i++) {
            candidate_logits[c * 64 + i] = 1.0f;
            draft_logits[c * 64 + i] = 0.5f;
        }
    }
    for (int c = 8; c < 16; c++) {
        for (int i = 0; i < 64; i++) {
            candidate_logits[c * 64 + i] = 0.1f;
            draft_logits[c * 64 + i] = 1.0f;
        }
    }
    
    // Tree mask
    memset(tree_mask, 0, sizeof(tree_mask));
    *(uint16_t*)tree_mask = 0xFFFF;
    for (int i = 0; i < 16; i++) {
        tree_mask[16 + i] = 0.5f;
    }
    
    uint64_t start = ReadTSC();
    uint32_t accept_mask = TreeAttentionVerify_AVX512_Export(
        candidate_logits, draft_logits, tree_mask,
        output_probs, 16, 0.6f
    );
    uint64_t end = ReadTSC();
    result.cycles = end - start;
    
    // Expect first 8 accepted (bits 0-7 set)
    if (accept_mask != 0x00FF) {
        result.error_msg = "Unexpected acceptance pattern";
        return result;
    }
    
    result.passed = true;
    return result;
}

// Test 4: KV Cache Invalidation
TestResult Test_KVCacheInvalidation() {
    TestResult result = {"KVCacheInvalidation", false, 0, nullptr};
    
    ALIGN64 uint8_t kv_cache[16 * 64];
    
    // Initialize with non-zero values
    memset(kv_cache, 0xAB, sizeof(kv_cache));
    
    // Reject entries 2, 3, 5, 7 (bits 2,3,5,7 = 0x00AC)
    uint32_t rejection_mask = 0x00AC;
    
    uint64_t start = ReadTSC();
    KVCacheInvalidate_AVX512_Export(kv_cache, rejection_mask, 64);
    uint64_t end = ReadTSC();
    result.cycles = end - start;
    
    // Verify rejected entries are zeroed
    bool valid = true;
    for (int i = 0; i < 16; i++) {
        bool should_be_zero = (rejection_mask >> i) & 1;
        for (int j = 0; j < 64; j++) {
            uint8_t val = kv_cache[i * 64 + j];
            if (should_be_zero && val != 0) {
                valid = false;
                break;
            }
            if (!should_be_zero && val != 0xAB) {
                valid = false;
                break;
            }
        }
    }
    
    if (!valid) {
        result.error_msg = "KV cache invalidation failed";
        return result;
    }
    
    result.passed = true;
    return result;
}

// Test 5: Boundary condition (num_candidates != 16)
TestResult Test_InvalidCandidateCount() {
    TestResult result = {"InvalidCandidateCount", false, 0, nullptr};
    
    ALIGN64 float candidate_logits[16 * 64];
    ALIGN64 float draft_logits[16 * 64];
    ALIGN64 float tree_mask[64];
    ALIGN64 float output_probs[16];
    
    memset(candidate_logits, 0, sizeof(candidate_logits));
    memset(draft_logits, 0, sizeof(draft_logits));
    memset(tree_mask, 0, sizeof(tree_mask));
    
    // Call with invalid count (8 instead of 16)
    uint32_t accept_mask = TreeAttentionVerify_AVX512_Export(
        candidate_logits, draft_logits, tree_mask,
        output_probs, 8, 0.6f
    );
    
    // Should return 0 (all rejected) for invalid input
    if (accept_mask != 0) {
        result.error_msg = "Should return 0 for invalid candidate count";
        return result;
    }
    
    result.passed = true;
    return result;
}

// Test 6: Feature detection
TestResult Test_AVX512Detection() {
    TestResult result = {"AVX512Detection", false, 0, nullptr};
    
    int has_avx512 = HasAVX512F_Export();
    
    // Just verify the function returns 0 or 1
    if (has_avx512 != 0 && has_avx512 != 1) {
        result.error_msg = "Invalid return from HasAVX512F";
        return result;
    }
    
    result.passed = true;
    return result;
}

//============================================================================
// Performance Benchmark
//============================================================================

void RunPerformanceBenchmark() {
    printf("\n=== Performance Benchmark ===\n");
    
    if (!HasAVX512F_Export()) {
        printf("AVX-512 not supported, skipping benchmark\n");
        return;
    }
    
    ALIGN64 float candidate_logits[16 * 64];
    ALIGN64 float draft_logits[16 * 64];
    ALIGN64 float tree_mask[64];
    ALIGN64 float output_probs[16];
    
    // Initialize test data
    for (int i = 0; i < 16 * 64; i++) {
        candidate_logits[i] = 0.5f;
        draft_logits[i] = 0.5f;
    }
    memset(tree_mask, 0, sizeof(tree_mask));
    *(uint16_t*)tree_mask = 0xFFFF;
    for (int i = 0; i < 16; i++) {
        tree_mask[16 + i] = 0.5f;
    }
    
    const int ITERATIONS = 10000;
    uint64_t total_cycles = 0;
    uint64_t min_cycles = ~0ULL;
    uint64_t max_cycles = 0;
    
    // Warmup
    for (int i = 0; i < 100; i++) {
        TreeAttentionVerify_AVX512_Export(
            candidate_logits, draft_logits, tree_mask,
            output_probs, 16, 0.6f
        );
    }
    
    // Benchmark
    for (int i = 0; i < ITERATIONS; i++) {
        uint64_t start = ReadTSC();
        TreeAttentionVerify_AVX512_Export(
            candidate_logits, draft_logits, tree_mask,
            output_probs, 16, 0.6f
        );
        uint64_t end = ReadTSC();
        
        uint64_t cycles = end - start;
        total_cycles += cycles;
        if (cycles < min_cycles) min_cycles = cycles;
        if (cycles > max_cycles) max_cycles = cycles;
    }
    
    double avg_cycles = (double)total_cycles / ITERATIONS;
    
    printf("Iterations: %d\n", ITERATIONS);
    printf("Min cycles: %llu\n", min_cycles);
    printf("Max cycles: %llu\n", max_cycles);
    printf("Avg cycles: %.2f\n", avg_cycles);
    printf("Est. TPS @ 3.5GHz: %.0f\n", 3.5e9 / avg_cycles);
}

//============================================================================
// Main
//============================================================================

int main() {
    printf("VAL-032 Speculative Decoder Smoke Test (Intrinsics)\n");
    printf("===================================================\n\n");
    
    // Check AVX-512 support
    printf("AVX-512 Support: %s\n\n", 
        HasAVX512F_Export() ? "YES" : "NO");
    
    // Run tests
    TestResult tests[] = {
        Test_AVX512Detection(),
        Test_AllAccept(),
        Test_AllReject(),
        Test_PartialAccept(),
        Test_KVCacheInvalidation(),
        Test_InvalidCandidateCount()
    };
    
    int passed = 0;
    int failed = 0;
    
    printf("Test Results:\n");
    printf("-------------\n");
    
    for (const auto& test : tests) {
        printf("%-25s: %s", test.name, test.passed ? "PASS" : "FAIL");
        if (test.cycles > 0) {
            printf(" (%llu cycles)", test.cycles);
        }
        if (!test.passed && test.error_msg) {
            printf(" - %s", test.error_msg);
        }
        printf("\n");
        
        if (test.passed) passed++;
        else failed++;
    }
    
    printf("\n");
    printf("Total: %d passed, %d failed\n", passed, failed);
    
    // Run performance benchmark
    RunPerformanceBenchmark();
    
    return failed > 0 ? 1 : 0;
}
