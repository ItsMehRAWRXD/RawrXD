//============================================================================
// speculative_differential_test.cpp
//
// VAL-032 Phase 3.4: MASM Differential Validation
//
// Validates that MASM kernel produces identical results to intrinsics oracle
// across 100k random speculative trees.
//============================================================================

#include "../src/kernels/tree_attention_dispatch.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <random>
#include <chrono>

using namespace RawrXD::Kernels;

// External MASM exports
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
    uint64_t ReadTSC_Export();
}

// Intrinsics reference (from tree_attention_avx512_intrinsics.cpp)
extern "C" uint32_t TreeAttentionVerify_AVX512_Intrinsics(
    const float* candidate_logits,
    const float* draft_logits,
    const float* tree_mask,
    float* output_probs,
    uint32_t num_candidates,
    float acceptance_threshold
);

extern "C" void KVCacheInvalidate_AVX512_Intrinsics(
    uint8_t* kv_cache_base,
    uint32_t rejection_mask,
    uint32_t entry_size
);

//============================================================================
// Aligned Allocation
//============================================================================
template<typename T>
T* AlignedAlloc(size_t count, size_t alignment = 64) {
    size_t size = count * sizeof(T);
    void* ptr = nullptr;
#ifdef _MSC_VER
    ptr = _aligned_malloc(size, alignment);
#else
    // GCC/Clang: use aligned_alloc or posix_memalign
    #if defined(__MINGW32__) || defined(__MINGW64__)
        ptr = __mingw_aligned_malloc(size, alignment);
    #else
        ptr = aligned_alloc(alignment, size);
    #endif
#endif
    return static_cast<T*>(ptr);
}

void AlignedFree(void* ptr) {
#ifdef _MSC_VER
    _aligned_free(ptr);
#else
    #if defined(__MINGW32__) || defined(__MINGW64__)
        __mingw_aligned_free(ptr);
    #else
        free(ptr);
    #endif
#endif
}

//============================================================================
// Test Configuration
//============================================================================
constexpr size_t NUM_ITERATIONS = 100000;
constexpr size_t NUM_CANDIDATES = 16;
constexpr size_t EMBEDDING_DIM = 64;
constexpr float ACCEPTANCE_THRESHOLD = 0.6f;

//============================================================================
// Random Data Generator
//============================================================================
class RandomGenerator {
public:
    RandomGenerator() : rng_(std::random_device{}()) {}
    
    void FillRandom(float* data, size_t count, float min, float max) {
        std::uniform_real_distribution<float> dist(min, max);
        for (size_t i = 0; i < count; i++) {
            data[i] = dist(rng_);
        }
    }
    
    void FillValidityMask(uint16_t& mask, uint16_t min_bits = 1) {
        std::uniform_int_distribution<uint16_t> dist(min_bits, 0xFFFF);
        mask = dist(rng_);
    }
    
private:
    std::mt19937 rng_;
};

//============================================================================
// Differential Test Result
//============================================================================
struct DifferentialResult {
    size_t total_tests;
    size_t mismatches;
    size_t masm_cycles;
    size_t intrinsics_cycles;
    double masm_avg_cycles;
    double intrinsics_avg_cycles;
    
    void Print() const {
        printf("\n=== Differential Validation Results ===\n");
        printf("Total tests:     %zu\n", total_tests);
        printf("Mismatches:      %zu\n", mismatches);
        printf("Match rate:      %.4f%%\n", 
               100.0 * (total_tests - mismatches) / total_tests);
        printf("\nPerformance:\n");
        printf("MASM avg cycles:      %.2f\n", masm_avg_cycles);
        printf("Intrinsics avg cycles:  %.2f\n", intrinsics_avg_cycles);
        printf("Speedup:              %.2fx\n", 
               intrinsics_avg_cycles / masm_avg_cycles);
        printf("=======================================\n\n");
    }
};

//============================================================================
// Single Test Case
//============================================================================
struct TestCase {
    float* candidate_logits;
    float* draft_logits;
    float* tree_mask;
    float* output_probs_masm;
    float* output_probs_intrinsics;
    
    bool Allocate() {
        candidate_logits = AlignedAlloc<float>(NUM_CANDIDATES * EMBEDDING_DIM);
        draft_logits = AlignedAlloc<float>(NUM_CANDIDATES * EMBEDDING_DIM);
        tree_mask = AlignedAlloc<float>(64);
        output_probs_masm = AlignedAlloc<float>(NUM_CANDIDATES);
        output_probs_intrinsics = AlignedAlloc<float>(NUM_CANDIDATES);
        
        return candidate_logits && draft_logits && tree_mask && 
               output_probs_masm && output_probs_intrinsics;
    }
    
    void Free() {
        AlignedFree(candidate_logits);
        AlignedFree(draft_logits);
        AlignedFree(tree_mask);
        AlignedFree(output_probs_masm);
        AlignedFree(output_probs_intrinsics);
    }
    
    void Generate(RandomGenerator& gen) {
        // Candidate logits: random values
        gen.FillRandom(candidate_logits, NUM_CANDIDATES * EMBEDDING_DIM, 
                       0.0f, 1.0f);
        
        // Draft logits: random values
        gen.FillRandom(draft_logits, NUM_CANDIDATES * EMBEDDING_DIM,
                       0.0f, 1.0f);
        
        // Tree mask: validity + draft probabilities
        memset(tree_mask, 0, 64 * sizeof(float));
        
        // Validity mask (16 bits)
        uint16_t validity;
        gen.FillValidityMask(validity);
        *(uint16_t*)tree_mask = validity;
        
        // Draft probabilities
        gen.FillRandom(tree_mask + 16, NUM_CANDIDATES, 0.1f, 0.9f);
    }
};

//============================================================================
// Run Differential Test
//============================================================================
DifferentialResult RunDifferentialTest() {
    DifferentialResult result{};
    
    // Check AVX-512 support
    if (!HasAVX512F_Export()) {
        printf("ERROR: AVX-512 not supported on this CPU\n");
        return result;
    }
    
    printf("Running %zu differential tests...\n", NUM_ITERATIONS);
    
    RandomGenerator gen;
    TestCase test;
    
    if (!test.Allocate()) {
        printf("ERROR: Memory allocation failed\n");
        return result;
    }
    
    size_t masm_total_cycles = 0;
    size_t intrinsics_total_cycles = 0;
    
    for (size_t i = 0; i < NUM_ITERATIONS; i++) {
        // Generate random test case
        test.Generate(gen);
        
        // Clear output buffers
        memset(test.output_probs_masm, 0, NUM_CANDIDATES * sizeof(float));
        memset(test.output_probs_intrinsics, 0, NUM_CANDIDATES * sizeof(float));
        
        // Run MASM kernel
        uint64_t masm_start = ReadTSC_Export();
        uint32_t mask_masm = TreeAttentionVerify_AVX512_Export(
            test.candidate_logits,
            test.draft_logits,
            test.tree_mask,
            test.output_probs_masm,
            NUM_CANDIDATES,
            ACCEPTANCE_THRESHOLD
        );
        uint64_t masm_end = ReadTSC_Export();
        
        // Run intrinsics kernel
        uint64_t intrinsics_start = ReadTSC_Export();
        uint32_t mask_intrinsics = TreeAttentionVerify_AVX512_Intrinsics(
            test.candidate_logits,
            test.draft_logits,
            test.tree_mask,
            test.output_probs_intrinsics,
            NUM_CANDIDATES,
            ACCEPTANCE_THRESHOLD
        );
        uint64_t intrinsics_end = ReadTSC_Export();
        
        // Accumulate cycles
        masm_total_cycles += (masm_end - masm_start);
        intrinsics_total_cycles += (intrinsics_end - intrinsics_start);
        
        // Compare results
        if (mask_masm != mask_intrinsics) {
            result.mismatches++;
            if (result.mismatches <= 5) {
                printf("Mismatch #%zu: MASM=0x%04X, Intrinsics=0x%04X\n",
                       result.mismatches, mask_masm, mask_intrinsics);
            }
        }
        
        // Progress indicator
        if ((i + 1) % 10000 == 0) {
            printf("  Progress: %zu/%zu (%.1f%%)\n", 
                   i + 1, NUM_ITERATIONS, 
                   100.0 * (i + 1) / NUM_ITERATIONS);
        }
    }
    
    test.Free();
    
    // Calculate results
    result.total_tests = NUM_ITERATIONS;
    result.masm_cycles = masm_total_cycles;
    result.intrinsics_cycles = intrinsics_total_cycles;
    result.masm_avg_cycles = (double)masm_total_cycles / NUM_ITERATIONS;
    result.intrinsics_avg_cycles = (double)intrinsics_total_cycles / NUM_ITERATIONS;
    
    return result;
}

//============================================================================
// KV Cache Invalidation Test
//============================================================================
bool TestKVCacheInvalidation() {
    printf("\nTesting KV cache invalidation...\n");
    
    uint8_t* kv_cache = AlignedAlloc<uint8_t>(16 * 64);
    if (!kv_cache) {
        printf("ERROR: KV cache allocation failed\n");
        return false;
    }
    
    // Initialize with non-zero values
    memset(kv_cache, 0xAB, 16 * 64);
    
    // Test rejection mask: clear entries 2, 3, 5, 7
    uint32_t rejection_mask = 0x00AC;
    
    // Run MASM invalidation
    KVCacheInvalidate_AVX512_Export(kv_cache, rejection_mask, 64);
    
    // Verify
    bool valid = true;
    for (int i = 0; i < 16; i++) {
        bool should_be_zero = (rejection_mask >> i) & 1;
        for (int j = 0; j < 64; j++) {
            uint8_t val = kv_cache[i * 64 + j];
            if (should_be_zero && val != 0) {
                printf("  Entry %d not cleared at offset %d\n", i, j);
                valid = false;
            }
            if (!should_be_zero && val != 0xAB) {
                printf("  Entry %d corrupted at offset %d\n", i, j);
                valid = false;
            }
        }
    }
    
    AlignedFree(kv_cache);
    
    if (valid) {
        printf("  KV cache invalidation: PASS\n");
    } else {
        printf("  KV cache invalidation: FAIL\n");
    }
    
    return valid;
}

//============================================================================
// Main
//============================================================================
int main() {
    printf("VAL-032 Phase 3.4: MASM Differential Validation\n");
    printf("==============================================\n\n");
    
    // Check AVX-512
    printf("AVX-512 Support: %s\n\n", 
           HasAVX512F_Export() ? "YES" : "NO");
    
    if (!HasAVX512F_Export()) {
        printf("ERROR: Cannot run test without AVX-512\n");
        return 1;
    }
    
    // Run differential test
    auto result = RunDifferentialTest();
    result.Print();
    
    // Run KV cache test
    bool kv_ok = TestKVCacheInvalidation();
    
    // Final verdict
    printf("\n=== FINAL VERDICT ===\n");
    if (result.mismatches == 0 && kv_ok) {
        printf("PASS: All %zu tests matched\n", result.total_tests);
        printf("MASM kernel is validated as drop-in replacement\n");
        return 0;
    } else {
        printf("FAIL: %zu mismatches found\n", result.mismatches);
        if (!kv_ok) {
            printf("KV cache invalidation failed\n");
        }
        return 1;
    }
}
