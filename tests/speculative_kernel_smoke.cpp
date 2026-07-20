// ============================================================================
// VAL-032: Speculative Decoder Kernel Smoke Test
// B → A → C Validation Sequence: Kernel Isolation
//
// Tests:
//   1. Mask verification (capture k5 before invalidation)
//   2. Boundary conditions (full accept, full reject)
//   3. Cycle-accurate timing (RDTSC)
//   4. ABI compliance (register preservation)
// ============================================================================

#include <iostream>
#include <cstring>
#include <cstdint>
#include <cmath>
#include <vector>
#include <chrono>
#include <immintrin.h>

// ============================================================================
// Kernel Interface (matches MASM implementation)
// ============================================================================
extern "C" {
    // Returns rejection mask in RAX (1 = reject, 0 = accept)
    // RCX = Q_ptr (64-byte aligned)
    // RDX = K_ptr (64-byte aligned)
    // R8  = TreeMask_ptr (64-byte aligned)
    // R9  = Output_probs (64-byte aligned)
    // [RSP+40] = num_candidates
    uint64_t TreeVerify_Batch_4x4(
        const float* Q,
        const float* K,
        const uint8_t* treeMask,
        float* outputProbs,
        uint32_t numCandidates
    );
    
    // Check if AVX-512 is available
    bool TreeAttention_HasAVX512();
}

// ============================================================================
// Cycle Counter (RDTSC with serialization)
// ============================================================================
inline uint64_t ReadTSC() {
    _mm_lfence();           // Serialize pipeline
    uint64_t tsc = __rdtsc();
    _mm_lfence();           // Ensure RDTSC completes
    return tsc;
}

// ============================================================================
// Test Utilities
// ============================================================================
class TestHarness {
public:
    static constexpr size_t ALIGNMENT = 64;
    static constexpr size_t HEAD_DIM = 64;      // 64 floats per head
    static constexpr size_t NUM_CANDIDATES = 16; // 4x4 tree
    
    struct TestVectors {
        alignas(64) float Q[HEAD_DIM];
        alignas(64) float K[NUM_CANDIDATES * HEAD_DIM];
        alignas(64) uint8_t treeMask[NUM_CANDIDATES];
        alignas(64) float outputProbs[NUM_CANDIDATES];
    };
    
    TestHarness() {
        vectors_ = static_cast<TestVectors*>(_aligned_malloc(sizeof(TestVectors), ALIGNMENT));
        if (!vectors_) {
            throw std::runtime_error("Failed to allocate aligned memory");
        }
    }
    
    ~TestHarness() {
        _aligned_free(vectors_);
    }
    
    // Test 1: Zero rejection (all tokens accepted)
    bool TestZeroRejection() {
        std::cout << "\n=== Test: Zero Rejection (All Accept) ===\n";
        
        // Setup: All candidates valid, high scores
        SetupDeterministicVectors(/*acceptAll=*/true);
        
        uint64_t startCycles = ReadTSC();
        uint64_t rejectionMask = TreeVerify_Batch_4x4(
            vectors_->Q,
            vectors_->K,
            vectors_->treeMask,
            vectors_->outputProbs,
            NUM_CANDIDATES
        );
        uint64_t endCycles = ReadTSC();
        
        std::cout << "  Rejection mask: 0x" << std::hex << rejectionMask << std::dec << "\n";
        std::cout << "  Expected: 0x0000 (all accepted)\n";
        std::cout << "  Cycles: " << (endCycles - startCycles) << "\n";
        
        // Verify: rejection mask should be 0
        bool pass = (rejectionMask == 0);
        
        // Verify output probabilities are valid (sum to ~1.0)
        float sum = 0.0f;
        for (int i = 0; i < NUM_CANDIDATES; i++) {
            sum += vectors_->outputProbs[i];
        }
        std::cout << "  Output prob sum: " << sum << " (expected ~1.0)\n";
        pass = pass && (sum > 0.99f && sum < 1.01f);
        
        std::cout << "  Result: " << (pass ? "PASS" : "FAIL") << "\n";
        return pass;
    }
    
    // Test 2: Full rejection (all tokens rejected)
    bool TestFullRejection() {
        std::cout << "\n=== Test: Full Rejection (All Reject) ===\n";
        
        // Setup: All candidates invalid (masked out)
        SetupDeterministicVectors(/*acceptAll=*/false);
        
        uint64_t startCycles = ReadTSC();
        uint64_t rejectionMask = TreeVerify_Batch_4x4(
            vectors_->Q,
            vectors_->K,
            vectors_->treeMask,
            vectors_->outputProbs,
            NUM_CANDIDATES
        );
        uint64_t endCycles = ReadTSC();
        
        std::cout << "  Rejection mask: 0x" << std::hex << rejectionMask << std::dec << "\n";
        std::cout << "  Expected: 0xFFFF (all rejected)\n";
        std::cout << "  Cycles: " << (endCycles - startCycles) << "\n";
        
        // Verify: rejection mask should be 0xFFFF (all 16 bits set)
        bool pass = (rejectionMask == 0xFFFF);
        
        std::cout << "  Result: " << (pass ? "PASS" : "FAIL") << "\n";
        return pass;
    }
    
    // Test 3: Partial rejection (mixed pattern)
    bool TestPartialRejection() {
        std::cout << "\n=== Test: Partial Rejection (Mixed) ===\n";
        
        // Setup: Reject candidates 2, 3, 6, 7 (bits 0x00CC)
        SetupMixedVectors(/*rejectMask=*/0x00CC);
        
        uint64_t startCycles = ReadTSC();
        uint64_t rejectionMask = TreeVerify_Batch_4x4(
            vectors_->Q,
            vectors_->K,
            vectors_->treeMask,
            vectors_->outputProbs,
            NUM_CANDIDATES
        );
        uint64_t endCycles = ReadTSC();
        
        std::cout << "  Rejection mask: 0x" << std::hex << rejectionMask << std::dec << "\n";
        std::cout << "  Expected: 0x00CC (candidates 2,3,6,7 rejected)\n";
        std::cout << "  Cycles: " << (endCycles - startCycles) << "\n";
        
        bool pass = (rejectionMask == 0x00CC);
        
        // Verify accepted candidates have valid probabilities
        for (int i = 0; i < NUM_CANDIDATES; i++) {
            bool rejected = (rejectionMask >> i) & 1;
            if (!rejected) {
                // Accepted candidate should have valid probability
                if (vectors_->outputProbs[i] <= 0.0f || vectors_->outputProbs[i] > 1.0f) {
                    std::cout << "  ERROR: Accepted candidate " << i 
                              << " has invalid prob: " << vectors_->outputProbs[i] << "\n";
                    pass = false;
                }
            }
        }
        
        std::cout << "  Result: " << (pass ? "PASS" : "FAIL") << "\n";
        return pass;
    }
    
    // Test 4: Cycle count benchmark (1000 iterations)
    bool TestCycleBenchmark() {
        std::cout << "\n=== Test: Cycle Benchmark (1000 iterations) ===\n";
        
        SetupDeterministicVectors(/*acceptAll=*/true);
        
        // Warmup
        for (int i = 0; i < 100; i++) {
            TreeVerify_Batch_4x4(
                vectors_->Q, vectors_->K, vectors_->treeMask,
                vectors_->outputProbs, NUM_CANDIDATES
            );
        }
        
        // Benchmark
        std::vector<uint64_t> cycles;
        cycles.reserve(1000);
        
        for (int i = 0; i < 1000; i++) {
            uint64_t start = ReadTSC();
            TreeVerify_Batch_4x4(
                vectors_->Q, vectors_->K, vectors_->treeMask,
                vectors_->outputProbs, NUM_CANDIDATES
            );
            uint64_t end = ReadTSC();
            cycles.push_back(end - start);
        }
        
        // Statistics
        uint64_t minCycles = *std::min_element(cycles.begin(), cycles.end());
        uint64_t maxCycles = *std::max_element(cycles.begin(), cycles.end());
        uint64_t avgCycles = std::accumulate(cycles.begin(), cycles.end(), 0ULL) / cycles.size();
        
        std::cout << "  Min cycles: " << minCycles << "\n";
        std::cout << "  Max cycles: " << maxCycles << "\n";
        std::cout << "  Avg cycles: " << avgCycles << "\n";
        std::cout << "  Estimated TPS: " << (3.5e9 / avgCycles) << " (at 3.5GHz)\n";
        
        // Pass if average is under 2000 cycles (target for 2K TPS)
        bool pass = (avgCycles < 2000);
        std::cout << "  Result: " << (pass ? "PASS" : "FAIL") << "\n";
        return pass;
    }
    
    // Test 5: ABI compliance (register preservation)
    bool TestABICompliance() {
        std::cout << "\n=== Test: ABI Compliance ===\n";
        
        // Set up non-volatile registers with sentinel values
        uint64_t rbx_before = 0xDEADBEEFCAFEBABEULL;
        uint64_t r12_before = 0xBADC0FFEE0DDF00DULL;
        uint64_t r13_before = 0xFEEDFACEF00DC0DEULL;
        uint64_t r14_before = 0xC0FFEE1234567890ULL;
        uint64_t r15_before = 0xF00D9876543210ABULL;
        
        // Call kernel (compiler will preserve registers)
        SetupDeterministicVectors(/*acceptAll=*/true);
        
        __asm {
            mov rbx, rbx_before
            mov r12, r12_before
            mov r13, r13_before
            mov r14, r14_before
            mov r15, r15_before
        }
        
        TreeVerify_Batch_4x4(
            vectors_->Q,
            vectors_->K,
            vectors_->treeMask,
            vectors_->outputProbs,
            NUM_CANDIDATES
        );
        
        uint64_t rbx_after, r12_after, r13_after, r14_after, r15_after;
        __asm {
            mov rbx_after, rbx
            mov r12_after, r12
            mov r13_after, r13
            mov r14_after, r14
            mov r15_after, r15
        }
        
        bool pass = true;
        if (rbx_after != rbx_before) {
            std::cout << "  FAIL: RBX corrupted (0x" << std::hex << rbx_after 
                      << " != 0x" << rbx_before << ")\n";
            pass = false;
        }
        if (r12_after != r12_before) {
            std::cout << "  FAIL: R12 corrupted (0x" << std::hex << r12_after 
                      << " != 0x" << r12_before << ")\n";
            pass = false;
        }
        if (r13_after != r13_before) {
            std::cout << "  FAIL: R13 corrupted (0x" << std::hex << r13_after 
                      << " != 0x" << r13_before << ")\n";
            pass = false;
        }
        if (r14_after != r14_before) {
            std::cout << "  FAIL: R14 corrupted (0x" << std::hex << r14_after 
                      << " != 0x" << r14_before << ")\n";
            pass = false;
        }
        if (r15_after != r15_before) {
            std::cout << "  FAIL: R15 corrupted (0x" << std::hex << r15_after 
                      << " != 0x" << r15_before << ")\n";
            pass = false;
        }
        
        if (pass) {
            std::cout << "  All non-volatile registers preserved\n";
        }
        std::cout << "  Result: " << (pass ? "PASS" : "FAIL") << "\n";
        return pass;
    }

private:
    TestVectors* vectors_;
    
    void SetupDeterministicVectors(bool acceptAll) {
        // Q vector: normalized random values
        for (int i = 0; i < HEAD_DIM; i++) {
            vectors_->Q[i] = static_cast<float>(i % 8) / 8.0f;
        }
        
        // K vectors: orthogonal to Q for high scores
        for (int c = 0; c < NUM_CANDIDATES; c++) {
            for (int i = 0; i < HEAD_DIM; i++) {
                // Create varying dot products
                vectors_->K[c * HEAD_DIM + i] = 
                    vectors_->Q[i] * (0.8f + 0.2f * (c % 4) / 4.0f);
            }
        }
        
        // Tree mask: 1 = valid, 0 = invalid (masked out)
        if (acceptAll) {
            memset(vectors_->treeMask, 0xFF, NUM_CANDIDATES); // All valid
        } else {
            memset(vectors_->treeMask, 0x00, NUM_CANDIDATES); // All invalid
        }
        
        // Clear output
        memset(vectors_->outputProbs, 0, sizeof(vectors_->outputProbs));
    }
    
    void SetupMixedVectors(uint16_t rejectMask) {
        // Q and K same as deterministic
        for (int i = 0; i < HEAD_DIM; i++) {
            vectors_->Q[i] = static_cast<float>(i % 8) / 8.0f;
        }
        for (int c = 0; c < NUM_CANDIDATES; c++) {
            for (int i = 0; i < HEAD_DIM; i++) {
                vectors_->K[c * HEAD_DIM + i] = vectors_->Q[i] * 0.9f;
            }
        }
        
        // Tree mask based on rejectMask
        for (int i = 0; i < NUM_CANDIDATES; i++) {
            vectors_->treeMask[i] = ((rejectMask >> i) & 1) ? 0x00 : 0xFF;
        }
        
        memset(vectors_->outputProbs, 0, sizeof(vectors_->outputProbs));
    }
};

// ============================================================================
// Main Entry Point
// ============================================================================
int main() {
    std::cout << "============================================================\n";
    std::cout << "VAL-032: Speculative Decoder Kernel Smoke Test\n";
    std::cout << "============================================================\n";
    
    // Check AVX-512 support
    if (!TreeAttention_HasAVX512()) {
        std::cerr << "ERROR: AVX-512 not supported on this CPU\n";
        return 1;
    }
    std::cout << "AVX-512: Supported\n";
    
    try {
        TestHarness harness;
        
        int passed = 0;
        int total = 5;
        
        if (harness.TestZeroRejection()) passed++;
        if (harness.TestFullRejection()) passed++;
        if (harness.TestPartialRejection()) passed++;
        if (harness.TestCycleBenchmark()) passed++;
        if (harness.TestABICompliance()) passed++;
        
        std::cout << "\n============================================================\n";
        std::cout << "SUMMARY: " << passed << "/" << total << " tests passed\n";
        std::cout << "============================================================\n";
        
        return (passed == total) ? 0 : 1;
        
    } catch (const std::exception& e) {
        std::cerr << "FATAL: " << e.what() << "\n";
        return 1;
    }
}
