// ============================================================================
// VAL-032: Tree Attention Bridge
// C++ interface to branchless AVX-512 kernel
// ============================================================================

#pragma once

#include <cstdint>
#include <cstddef>

namespace rxd {
namespace inference {

// ============================================================================
// Tree Verification Result
// ============================================================================
struct TreeVerificationResult {
    uint64_t acceptanceMask;      // Bitmask: 1 = accepted, 0 = rejected
    uint64_t rejectionMask;       // Bitmask: 1 = rejected, 0 = accepted
    uint32_t acceptedCount;       // Number of accepted tokens (popcount of mask)
    float verifiedProbs[16];      // Probabilities for accepted positions
    uint64_t cycleCount;          // Kernel execution cycles (for profiling)
};

// ============================================================================
// Tree Attention Bridge
// 
// Provides C++ interface to branchless AVX-512 kernel
// Handles ABI compliance, alignment, and cycle counting
// ============================================================================
class TreeAttentionBridge {
public:
    TreeAttentionBridge();
    ~TreeAttentionBridge();
    
    // Initialize with KV cache base address
    bool Initialize(void* kvCacheBase, size_t kvCacheSize);
    
    // Verify 4x4 tree (16 candidates) branchlessly
    // All pointers must be 64-byte aligned
    TreeVerificationResult VerifyBatch4x4(
        const float* query,           // [256] floats - 64 bytes per candidate
        const float* keyCache,        // [16][256] - 16 candidates x 64 floats
        const float* treeMask,        // [16] - precomputed mask values
        const float* draftProbs,      // [16] - draft model probabilities
        float* outputProbs            // [16] - output verified probabilities
    );
    
    // Get last kernel execution cycles
    uint64_t GetLastCycleCount() const { return lastCycleCount_; }
    
    // Check if AVX-512 is available
    static bool IsAVX512Available();
    
private:
    void* kvCacheBase_ = nullptr;
    size_t kvCacheSize_ = 0;
    uint64_t lastCycleCount_ = 0;
    bool initialized_ = false;
};

// ============================================================================
// Extern C linkage for MASM kernel
// ============================================================================
extern "C" {
    // MASM kernel entry point
    // RCX = query, RDX = keyCache, R8 = treeMask, R9 = outputProbs
    // [RSP+40] = draftProbs, [RSP+48] = numCandidates
    // Returns: EAX = accepted count, RAX[63:32] = acceptance mask
    uint64_t __stdcall TreeVerify_Batch_4x4(
        const float* query,
        const float* keyCache,
        const float* treeMask,
        float* outputProbs,
        const float* draftProbs,
        uint32_t numCandidates
    );
}

// ============================================================================
// Cycle Counter (RDTSC)
// ============================================================================
class CycleCounter {
public:
    static inline uint64_t ReadTSC() {
        uint32_t eax, edx;
        __asm__ __volatile__ (
            "lfence\n\t"
            "rdtsc\n\t"
            : "=a"(eax), "=d"(edx)
            :
            : "memory"
        );
        return (static_cast<uint64_t>(edx) << 32) | eax;
    }
    
    static inline void Serialize() {
        __asm__ __volatile__ ("lfence" ::: "memory");
    }
};

} // namespace inference
} // namespace rxd
