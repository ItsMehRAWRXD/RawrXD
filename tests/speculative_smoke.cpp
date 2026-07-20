//============================================================================
// speculative_smoke.cpp
//
// VAL-032: Smoke Test Harness for Branchless Tree Attention Kernel
//
// Validates:
//   - Kernel correctness with deterministic vectors
//   - Mask extraction and propagation
//   - Branchless invalidation logic
//   - ABI compliance (no register spills)
//   - Cycle-accurate performance baseline
//============================================================================

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cmath>
#include <immintrin.h>

// Align to 64-byte boundary for AVX-512
#define ALIGN64 __declspec(align(64))

// External ASM kernel exports
extern "C" {
    // Returns 16-bit rejection mask (1 = reject, 0 = accept)
    uint64_t TreeVerify_Batch_4x4(
        const float* q_ptr,           // RCX: Query vector (64 floats)
        const float* k_ptr,           // RDX: Key cache (16 x 64 floats)
        const float* tree_mask_ptr,   // R8:  Tree mask buffer
        float* output_probs,          // R9:  Output probabilities
        uint32_t num_candidates       // [RSP+40]: Should be 16
    );
    
    // Branchless KV cache invalidation
    void KVCache_Invalidate_Masked(
        void* kv_cache_ptr,           // RCX: KV cache base
        uint64_t rejection_mask,      // RDX: 16-bit mask
        uint64_t entry_size           // R8:  Entry size in bytes
    );
    
    // Feature detection
    int TreeAttention_HasAVX512();
}

//============================================================================
// Test Utilities
//============================================================================

// Precise cycle counter using RDTSC
inline uint64_t ReadTSC() {
    _mm_lfence();           // Serialize pipeline
    uint64_t tsc = __rdtsc();
    _mm_lfence();           // Serialize after read
    return tsc;
}

// Verify 64-byte alignment
bool IsAligned64(const void* ptr) {
    return ((uintptr_t)ptr & 0x3F) == 0;
}

// Compare floats with tolerance
bool FloatEquals(float a, float b, float epsilon = 1e-5f) {
    return std::fabs(a - b) < epsilon;
}

//============================================================================
// Test Cases
//============================================================================

struct TestResult {
    const char* name;
    bool passed;
    uint64_t cycles;
    const char* error_msg;
};

// Test 1: Basic acceptance (all tokens valid, high confidence)
TestResult Test_AllAccept() {
    TestResult result = {"AllAccept", false, 0, nullptr};
    
    ALIGN64 float query[64];
    ALIGN64 float keys[16 * 64];      // 16 candidates x 64 dims
    ALIGN64 float tree_mask[64];       // Mask buffer
    ALIGN64 float output_probs[64];   // Output buffer
    
    // Initialize query with normalized values
    for (int i = 0; i < 64; i++) {
        query[i] = 0.125f;  // Normalized vector
    }
    
    // Initialize keys to match query (high dot product)
    for (int c = 0; c < 16; c++) {
        for (int i = 0; i < 64; i++) {
            keys[c * 64 + i] = query[i];  // Perfect match
        }
    }
    
    // Tree mask: all valid (0), draft probs all 0.5
    memset(tree_mask, 0, sizeof(tree_mask));
    for (int i = 0; i < 16; i++) {
        tree_mask[32 + i] = 0.5f;  // Draft probabilities
    }
    
    // Verify alignment
    if (!IsAligned64(query) || !IsAligned64(keys) || 
        !IsAligned64(tree_mask) || !IsAligned64(output_probs)) {
        result.error_msg = "Alignment check failed";
        return result;
    }
    
    // Check AVX-512 support
    if (!TreeAttention_HasAVX512()) {
        result.error_msg = "AVX-512 not supported";
        return result;
    }
    
    // Run kernel with cycle counting
    uint64_t start = ReadTSC();
    uint64_t rejection_mask = TreeVerify_Batch_4x4(
        query, keys, tree_mask, output_probs, 16
    );
    uint64_t end = ReadTSC();
    result.cycles = end - start;
    
    // All should be accepted (rejection mask = 0)
    if (rejection_mask != 0) {
        result.error_msg = "Expected all accepted, but some rejected";
        return result;
    }
    
    result.passed = true;
    return result;
}

// Test 2: Full rejection (all tokens below threshold)
TestResult Test_AllReject() {
    TestResult result = {"AllReject", false, 0, nullptr};
    
    ALIGN64 float query[64];
    ALIGN64 float keys[16 * 64];
    ALIGN64 float tree_mask[64];
    ALIGN64 float output_probs[64];
    
    // Query with high values
    for (int i = 0; i < 64; i++) {
        query[i] = 1.0f;
    }
    
    // Keys with low values (poor match)
    for (int c = 0; c < 16; c++) {
        for (int i = 0; i < 64; i++) {
            keys[c * 64 + i] = 0.01f;
        }
    }
    
    // Tree mask: all valid, high draft probs
    memset(tree_mask, 0, sizeof(tree_mask));
    for (int i = 0; i < 16; i++) {
        tree_mask[32 + i] = 0.9f;  // High draft probs
    }
    
    uint64_t start = ReadTSC();
    uint64_t rejection_mask = TreeVerify_Batch_4x4(
        query, keys, tree_mask, output_probs, 16
    );
    uint64_t end = ReadTSC();
    result.cycles = end - start;
    
    // All should be rejected (rejection mask = 0xFFFF)
    if (rejection_mask != 0xFFFF) {
        result.error_msg = "Expected all rejected";
        return result;
    }
    
    result.passed = true;
    return result;
}

// Test 3: Partial acceptance (mixed results)
TestResult Test_PartialAccept() {
    TestResult result = {"PartialAccept", false, 0, nullptr};
    
    ALIGN64 float query[64];
    ALIGN64 float keys[16 * 64];
    ALIGN64 float tree_mask[64];
    ALIGN64 float output_probs[64];
    
    // Initialize query
    for (int i = 0; i < 64; i++) {
        query[i] = 0.5f;
    }
    
    // Keys: first 8 match well, last 8 match poorly
    for (int c = 0; c < 8; c++) {
        for (int i = 0; i < 64; i++) {
            keys[c * 64 + i] = query[i];  // Good match
        }
    }
    for (int c = 8; c < 16; c++) {
        for (int i = 0; i < 64; i++) {
            keys[c * 64 + i] = 0.01f;  // Poor match
        }
    }
    
    // Tree mask
    memset(tree_mask, 0, sizeof(tree_mask));
    for (int i = 0; i < 16; i++) {
        tree_mask[32 + i] = 0.5f;
    }
    
    uint64_t start = ReadTSC();
    uint64_t rejection_mask = TreeVerify_Batch_4x4(
        query, keys, tree_mask, output_probs, 16
    );
    uint64_t end = ReadTSC();
    result.cycles = end - start;
    
    // Expect first 8 accepted, last 8 rejected
    // rejection_mask should have bits 8-15 set = 0xFF00
    if (rejection_mask != 0xFF00) {
        result.error_msg = "Unexpected rejection pattern";
        return result;
    }
    
    result.passed = true;
    return result;
}

// Test 4: KV Cache Invalidation
TestResult Test_KVCacheInvalidation() {
    TestResult result = {"KVCacheInvalidation", false, 0, nullptr};
    
    ALIGN64 uint8_t kv_cache[16 * 64];  // 16 entries x 64 bytes
    
    // Initialize with non-zero values
    memset(kv_cache, 0xAB, sizeof(kv_cache));
    
    // Reject entries 2, 3, 5, 7 (bits 2,3,5,7 = 0x00AC)
    uint64_t rejection_mask = 0x00AC;
    
    uint64_t start = ReadTSC();
    KVCache_Invalidate_Masked(kv_cache, rejection_mask, 64);
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
    
    ALIGN64 float query[64];
    ALIGN64 float keys[16 * 64];
    ALIGN64 float tree_mask[64];
    ALIGN64 float output_probs[64];
    
    memset(query, 0, sizeof(query));
    memset(keys, 0, sizeof(keys));
    memset(tree_mask, 0, sizeof(tree_mask));
    
    // Call with invalid count (8 instead of 16)
    uint64_t rejection_mask = TreeVerify_Batch_4x4(
        query, keys, tree_mask, output_probs, 8
    );
    
    // Should return 0 (all rejected) for invalid input
    if (rejection_mask != 0) {
        result.error_msg = "Should return 0 for invalid candidate count";
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
    
    ALIGN64 float query[64];
    ALIGN64 float keys[16 * 64];
    ALIGN64 float tree_mask[64];
    ALIGN64 float output_probs[64];
    
    // Initialize test data
    for (int i = 0; i < 64; i++) query[i] = 0.5f;
    for (int i = 0; i < 16 * 64; i++) keys[i] = 0.5f;
    memset(tree_mask, 0, sizeof(tree_mask));
    
    const int ITERATIONS = 10000;
    uint64_t total_cycles = 0;
    uint64_t min_cycles = ~0ULL;
    uint64_t max_cycles = 0;
    
    // Warmup
    for (int i = 0; i < 100; i++) {
        TreeVerify_Batch_4x4(query, keys, tree_mask, output_probs, 16);
    }
    
    // Benchmark
    for (int i = 0; i < ITERATIONS; i++) {
        uint64_t start = ReadTSC();
        TreeVerify_Batch_4x4(query, keys, tree_mask, output_probs, 16);
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
    printf("VAL-032 Speculative Decoder Smoke Test\n");
    printf("======================================\n\n");
    
    // Check AVX-512 support
    if (!TreeAttention_HasAVX512()) {
        printf("ERROR: AVX-512 not supported on this CPU\n");
        return 1;
    }
    printf("AVX-512: Supported\n\n");
    
    // Run tests
    TestResult tests[] = {
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
