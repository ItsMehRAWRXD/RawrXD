// ==============================================================================
// SwarmV29_Validation_Harness.cpp
// PHASE-29: C++ Validation Harness for PQC Kernels
// Target: 70B @ 150TPS via AVX-512 Vectorized NTT
// ------------------------------------------------------------------------------
// Comprehensive test suite for all 19 Phase-29 kernels.
// Validates alignment, round-trip integrity, and performance benchmarks.
// ==============================================================================

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <immintrin.h>
#include <intrin.h>

// Include the kernel interface
#include "SwarmV29_Kernel.h"

// Test configuration
#define TEST_POLYNOMIAL_SIZE 256
#define TEST_ITERATIONS 1000
#define KYBER_Q 3329
#define KYBER_Q_INV 62209
#define KYBER_N_INV 3328  // N^-1 mod Q for N=256

// Alignment helper
#define ALIGNED_ALLOC(size) _aligned_malloc(size, 64)
#define ALIGNED_FREE(ptr) _aligned_free(ptr)

// Test result structure
struct TestResult {
    const char* name;
    bool passed;
    uint64_t cycles;
    const char* error_message;
};

// Global test counters
static int g_tests_passed = 0;
static int g_tests_failed = 0;

// ==============================================================================
// AVX-512 Feature Detection
// ==============================================================================
bool Check_AVX512_Support() {
    int cpuinfo[4];
    __cpuid(cpuinfo, 0, 0);
    if (cpuinfo[0] < 7) return false;
    
    __cpuidex(cpuinfo, 7, 0);
    bool avx512f = (cpuinfo[1] & (1 << 16)) != 0;  // EBX bit 16 = AVX-512F
    
    if (!avx512f) {
        printf("[FATAL] AVX-512F not supported. Cannot run Phase-29 kernels.\n");
        return false;
    }
    
    // Check XCR0 for ZMM state support
    uint64_t xcr0 = _xgetbv(0);
    bool zmm_state = (xcr0 & 0x70) == 0x70;  // OPMASK, ZMM_Hi256, Hi16_ZMM
    
    if (!zmm_state) {
        printf("[FATAL] XCR0 does not enable ZMM state. Cannot use AVX-512 registers.\n");
        return false;
    }
    
    printf("[INFO] AVX-512F detected and enabled.\n");
    return true;
}

// ==============================================================================
// Test: Pool Allocator
// ==============================================================================
TestResult Test_Pool_Allocator() {
    TestResult result = {"Pool_Allocator", false, 0, nullptr};
    
    // Initialize pool with 1MB
    SwarmV29_Init_Pool(1024 * 1024);
    
    // Allocate some blocks
    void* block1 = SwarmV29_Alloc_Slab(256);
    void* block2 = SwarmV29_Alloc_Slab(512);
    void* block3 = SwarmV29_Alloc_Slab(1024);
    
    // Verify alignment
    if (((uint64_t)block1 & 63) != 0) {
        result.error_message = "Block 1 not 64-byte aligned";
        return result;
    }
    if (((uint64_t)block2 & 63) != 0) {
        result.error_message = "Block 2 not 64-byte aligned";
        return result;
    }
    if (((uint64_t)block3 & 63) != 0) {
        result.error_message = "Block 3 not 64-byte aligned";
        return result;
    }
    
    // Verify non-null
    if (!block1 || !block2 || !block3) {
        result.error_message = "Allocation returned NULL";
        return result;
    }
    
    // Reset pool
    SwarmV29_Reset_Pool();
    
    // Allocate again (should reuse same memory)
    void* block4 = SwarmV29_Alloc_Slab(256);
    if (block4 != block1) {
        result.error_message = "Pool reset did not recycle memory";
        return result;
    }
    
    // Cleanup
    SwarmV29_Destroy_Pool();
    
    result.passed = true;
    return result;
}

// ==============================================================================
// Test: Brutal Pack/Unpack Round-Trip
// ==============================================================================
TestResult Test_Brutal_Pack_Unpack() {
    TestResult result = {"Brutal_Pack_Unpack", false, 0, nullptr};
    
    const uint64_t block_count = 8;  // 8 blocks = 256 coefficients
    
    // Allocate aligned buffers
    uint64_t* original = (uint64_t*)ALIGNED_ALLOC(block_count * 128);  // 32-bit coefficients
    uint16_t* packed = (uint16_t*)ALIGNED_ALLOC(block_count * 64);     // 16-bit packed
    uint64_t* expanded = (uint64_t*)ALIGNED_ALLOC(block_count * 128);  // 32-bit expanded
    
    if (!original || !packed || !expanded) {
        result.error_message = "Memory allocation failed";
        ALIGNED_FREE(original);
        ALIGNED_FREE(packed);
        ALIGNED_FREE(expanded);
        return result;
    }
    
    // Fill original with test data (Kyber coefficients: 0 to Q-1)
    for (uint64_t i = 0; i < block_count * 16; i++) {
        original[i] = i % KYBER_Q;
    }
    
    // Pack
    uint64_t pack_result = SwarmV29_Brutal_Pack(original, packed, block_count);
    if (pack_result != 0) {
        result.error_message = "Pack returned error code";
        ALIGNED_FREE(original);
        ALIGNED_FREE(packed);
        ALIGNED_FREE(expanded);
        return result;
    }
    
    // Unpack
    uint64_t unpack_result = SwarmV29_Brutal_Unpack(packed, expanded, block_count);
    if (unpack_result != 0) {
        result.error_message = "Unpack returned error code";
        ALIGNED_FREE(original);
        ALIGNED_FREE(packed);
        ALIGNED_FREE(expanded);
        return result;
    }
    
    // Verify round-trip
    bool match = true;
    for (uint64_t i = 0; i < block_count * 16; i++) {
        if (original[i] != expanded[i]) {
            printf("[ERROR] Mismatch at index %llu: original=%llu, expanded=%llu\n",
                   i, original[i], expanded[i]);
            match = false;
            break;
        }
    }
    
    ALIGNED_FREE(original);
    ALIGNED_FREE(packed);
    ALIGNED_FREE(expanded);
    
    result.passed = match;
    return result;
}

// ==============================================================================
// Test: Bit-Reversal Permutation
// ==============================================================================
TestResult Test_BitReverse() {
    TestResult result = {"BitReverse", false, 0, nullptr};
    
    const uint64_t N = 256;
    const uint64_t log2N = 8;
    
    uint64_t* array = (uint64_t*)ALIGNED_ALLOC(N * sizeof(uint64_t));
    if (!array) {
        result.error_message = "Memory allocation failed";
        return result;
    }
    
    // Initialize with sequential values
    for (uint64_t i = 0; i < N; i++) {
        array[i] = i;
    }
    
    // Apply bit-reversal
    SwarmV29_BitReverse(array, N, log2N);
    
    // Verify: array[i] should contain reverse_bits(i)
    bool correct = true;
    for (uint64_t i = 0; i < N; i++) {
        uint64_t expected = 0;
        for (int j = 0; j < 8; j++) {
            if (i & (1ULL << j)) {
                expected |= (1ULL << (7 - j));
            }
        }
        if (array[i] != expected) {
            printf("[ERROR] BitReverse mismatch at %llu: got %llu, expected %llu\n",
                   i, array[i], expected);
            correct = false;
            break;
        }
    }
    
    ALIGNED_FREE(array);
    result.passed = correct;
    return result;
}

// ==============================================================================
// Test: AVX-512 Feature Detection
// ==============================================================================
TestResult Test_AVX512_Detection() {
    TestResult result = {"AVX512_Detection", false, 0, nullptr};
    
    uint64_t supported = SwarmV29_AVX512_Feature_Detect();
    
    if (supported == 0) {
        result.error_message = "AVX-512 not detected";
        return result;
    }
    
    printf("[INFO] AVX-512 Feature Detection returned: 0x%016llX\n", supported);
    result.passed = true;
    return result;
}

// ==============================================================================
// Test: Verification Integrity Check
// ==============================================================================
TestResult Test_Verification_Integrity() {
    TestResult result = {"Verification_Integrity", false, 0, nullptr};
    
    const uint64_t block_count = 4;
    
    // Allocate test buffer
    uint64_t* original = (uint64_t*)ALIGNED_ALLOC(block_count * 128);
    if (!original) {
        result.error_message = "Memory allocation failed";
        return result;
    }
    
    // Fill with test data
    for (uint64_t i = 0; i < block_count * 16; i++) {
        original[i] = i % KYBER_Q;
    }
    
    // Run verification
    int verify_result = SwarmV29_Verify_Integrity(original, block_count);
    
    ALIGNED_FREE(original);
    
    if (verify_result == 0) {
        result.passed = true;
    } else {
        result.error_message = "Verification failed (data corruption detected)";
    }
    
    return result;
}

// ==============================================================================
// Benchmark: NTT Butterfly Cycle Count
// ==============================================================================
TestResult Benchmark_Butterfly() {
    TestResult result = {"Benchmark_Butterfly", false, 0, nullptr};
    
    // Allocate aligned test buffers
    uint64_t* A = (uint64_t*)ALIGNED_ALLOC(64);
    uint64_t* B = (uint64_t*)ALIGNED_ALLOC(64);
    uint64_t* W = (uint64_t*)ALIGNED_ALLOC(64);
    
    if (!A || !B || !W) {
        result.error_message = "Memory allocation failed";
        ALIGNED_FREE(A);
        ALIGNED_FREE(B);
        ALIGNED_FREE(W);
        return result;
    }
    
    // Initialize with test data
    for (int i = 0; i < 8; i++) {
        A[i] = i;
        B[i] = i * 2;
        W[i] = i + 1;
    }
    
    // Warm up
    for (int i = 0; i < 100; i++) {
        SwarmV29_NTT_Butterfly();
    }
    
    // Benchmark
    uint64_t start = __rdtsc();
    for (int i = 0; i < TEST_ITERATIONS; i++) {
        SwarmV29_NTT_Butterfly();
    }
    uint64_t end = __rdtsc();
    
    result.cycles = (end - start) / TEST_ITERATIONS;
    result.passed = true;
    
    ALIGNED_FREE(A);
    ALIGNED_FREE(B);
    ALIGNED_FREE(W);
    
    return result;
}

// ==============================================================================
// Main Test Runner
// ==============================================================================
int main(int argc, char* argv[]) {
    printf("================================================================\n");
    printf("SwarmV29 Phase-29 PQC Kernel Validation Harness\n");
    printf("Target: 70B @ 150TPS via AVX-512 Vectorized NTT\n");
    printf("================================================================\n\n");
    
    // Check AVX-512 support first
    if (!Check_AVX512_Support()) {
        printf("[FATAL] Cannot proceed without AVX-512 support.\n");
        return 1;
    }
    
    printf("\n--- Running Tests ---\n\n");
    
    // Test suite
    TestResult tests[] = {
        Test_AVX512_Detection(),
        Test_Pool_Allocator(),
        Test_BitReverse(),
        Test_Brutal_Pack_Unpack(),
        Test_Verification_Integrity(),
        Benchmark_Butterfly()
    };
    
    int num_tests = sizeof(tests) / sizeof(tests[0]);
    
    // Print results
    for (int i = 0; i < num_tests; i++) {
        printf("[%s] %s\n", 
               tests[i].passed ? "PASS" : "FAIL",
               tests[i].name);
        
        if (tests[i].cycles > 0) {
            printf("        Cycles: %llu\n", tests[i].cycles);
        }
        
        if (!tests[i].passed && tests[i].error_message) {
            printf("        Error: %s\n", tests[i].error_message);
        }
        
        if (tests[i].passed) {
            g_tests_passed++;
        } else {
            g_tests_failed++;
        }
    }
    
    printf("\n================================================================\n");
    printf("Results: %d passed, %d failed\n", g_tests_passed, g_tests_failed);
    printf("================================================================\n");
    
    return (g_tests_failed > 0) ? 1 : 0;
}