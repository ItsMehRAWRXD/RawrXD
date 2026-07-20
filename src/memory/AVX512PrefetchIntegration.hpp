//=============================================================================
// RawrXD AVX-512 Prefetch Integration
// Phase 3C: Kernel-Memory Synergy
//
// Injects prefetch hints into AVX-512 kernels to hide DRAM latency.
// Provides:
// - Software pipelining (prefetch next block while computing current)
// - Distance-tuned prefetch (2-3 cache lines ahead)
// - Non-temporal stores for KV updates (bypass cache pollution)
// - Integration with KVResidencyScheduler for predictive prefetch
//
// This is the final link between the residency scheduler and compute.
//=============================================================================

#pragma once

#include "KVResidencyScheduler.hpp"
#include <cstdint>
#include <immintrin.h>

namespace RawrXD {
namespace Memory {

//=============================================================================
// Prefetch Configuration
//=============================================================================
struct PrefetchConfig {
    // Distance ahead to prefetch (in cache lines)
    // Tuned for DRAM latency ~100ns, AVX-512 throughput ~50μs
    static constexpr int PREFETCH_DISTANCE_LINES = 4;  // 256 bytes ahead
    
    // Prefetch locality hints
    // _MM_HINT_T0 = L1 cache
    // _MM_HINT_T1 = L2 cache  
    // _MM_HINT_T2 = L3 cache
    // _MM_HINT_NTA = Non-temporal (streaming)
    static constexpr int PREFETCH_HINT_K = _MM_HINT_T0;  // K in L1
    static constexpr int PREFETCH_HINT_V = _MM_HINT_T1;  // V in L2 (lower priority)
    static constexpr int PREFETCH_HINT_Q = _MM_HINT_T0;  // Q in L1
    
    // Non-temporal store threshold
    // Use streaming stores for writes > this size
    static constexpr size_t NTA_THRESHOLD = 4096;  // 4KB
};

//=============================================================================
// Prefetch Integration Context
// Maintains prefetch state across kernel invocations
//=============================================================================
class AVX512PrefetchContext {
public:
    AVX512PrefetchContext();
    
    // Initialize with sequence info
    void Initialize(uint64_t sequenceId, uint32_t startBlock, uint32_t numBlocks);
    
    // Reset for new computation
    void Reset();
    
    // Advance to next block
    void Advance();
    
    // Get current block being computed
    uint32_t GetCurrentBlock() const { return currentBlock_; }
    
    // Get block to prefetch (lookahead)
    uint32_t GetPrefetchBlock() const { return prefetchBlock_; }
    
    // Check if prefetch is valid
    bool HasValidPrefetch() const { return prefetchBlock_ < endBlock_; }
    
    // Get sequence ID
    uint64_t GetSequenceId() const { return sequenceId_; }
    
private:
    uint64_t sequenceId_ = 0;
    uint32_t currentBlock_ = 0;
    uint32_t prefetchBlock_ = 0;
    uint32_t startBlock_ = 0;
    uint32_t endBlock_ = 0;
};

//=============================================================================
// Prefetch Helpers
// Inline functions for kernel integration
//=============================================================================

// Prefetch K data for upcoming block
inline void PrefetchKData(const float* kData, int offset) {
    _mm_prefetch(
        reinterpret_cast<const char*>(kData + offset * 16),  // 16 floats = 64 bytes
        PrefetchConfig::PREFETCH_HINT_K
    );
}

// Prefetch V data for upcoming block
inline void PrefetchVData(const float* vData, int offset) {
    _mm_prefetch(
        reinterpret_cast<const char*>(vData + offset * 16),
        PrefetchConfig::PREFETCH_HINT_V
    );
}

// Prefetch Q data
inline void PrefetchQData(const float* qData, int offset) {
    _mm_prefetch(
        reinterpret_cast<const char*>(qData + offset * 16),
        PrefetchConfig::PREFETCH_HINT_Q
    );
}

// Non-temporal store for KV updates
inline void StreamStoreK(float* dest, __m512 value) {
    _mm512_stream_ps(dest, value);
}

inline void StreamStoreV(float* dest, __m512 value) {
    _mm512_stream_ps(dest, value);
}

// Prefetch entire cache line
inline void PrefetchCacheLine(const void* ptr, int hint) {
    _mm_prefetch(reinterpret_cast<const char*>(ptr), hint);
}

//=============================================================================
// Kernel Prefetch Wrapper
// Wraps AVX-512 kernels with prefetch logic
//=============================================================================
class KernelPrefetchWrapper {
public:
    KernelPrefetchWrapper(KVResidencyScheduler* scheduler);
    
    // Initialize prefetch context for a sequence
    void BeginSequence(uint64_t sequenceId, uint32_t numBlocks);
    
    // End sequence
    void EndSequence();
    
    // Prefetch next blocks based on context
    void PrefetchNextBlocks();
    
    // Get prefetch context
    AVX512PrefetchContext& GetContext() { return context_; }
    
    // Integration with residency scheduler
    void NotifyBlockAccess(uint32_t blockId);
    
private:
    KVResidencyScheduler* scheduler_;
    AVX512PrefetchContext context_;
    uint32_t prefetchLookahead_ = PrefetchConfig::PREFETCH_DISTANCE_LINES;
};

//=============================================================================
// Tree Attention with Prefetch
// Enhanced TreeAttention kernel with integrated prefetching
//=============================================================================
class TreeAttentionWithPrefetch {
public:
    struct Config {
        uint32_t headDim;
        uint32_t numHeads;
        bool enablePrefetch;
        bool useNonTemporalStores;
    };
    
    TreeAttentionWithPrefetch(const Config& config);
    
    // Set residency scheduler for predictive prefetch
    void SetResidencyScheduler(KVResidencyScheduler* scheduler);
    
    // Forward pass with prefetch integration
    void Forward(
        const float* Q,           // Query [numNodes, headDim]
        const float* K,           // Key [numNodes, headDim]
        const float* V,           // Value [numNodes, headDim]
        float* output,            // Output [numNodes, headDim]
        const void* treeBranches, // Tree structure
        uint32_t numNodes,        // Number of nodes
        uint64_t sequenceId       // For residency tracking
    );
    
    // Compute scores with prefetch
    void ComputeScoresWithPrefetch(
        const float* Q,
        const float* K,
        float* scores,
        uint32_t numNodes,
        uint64_t sequenceId
    );
    
private:
    Config config_;
    KVResidencyScheduler* scheduler_ = nullptr;
    AVX512PrefetchContext prefetchContext_;
    
    // Internal prefetch methods
    void PrefetchKForNode(uint32_t nodeIdx);
    void PrefetchVForNode(uint32_t nodeIdx);
    void PrefetchQForNode(uint32_t nodeIdx);
    
    // Record access to scheduler
    void RecordBlockAccess(uint32_t blockId);
};

//=============================================================================
// Assembly Prefetch Macros
// For use in .asm files
//=============================================================================

// These would be used in the actual assembly implementation
// For now, we provide C++ inline wrappers

// PREFETCHT0 - Prefetch to L1
#define RAWRXD_PREFETCH_L1(addr) \
    _mm_prefetch(reinterpret_cast<const char*>(addr), _MM_HINT_T0)

// PREFETCHT1 - Prefetch to L2
#define RAWRXD_PREFETCH_L2(addr) \
    _mm_prefetch(reinterpret_cast<const char*>(addr), _MM_HINT_T1)

// PREFETCHT2 - Prefetch to L3
#define RAWRXD_PREFETCH_L3(addr) \
    _mm_prefetch(reinterpret_cast<const char*>(addr), _MM_HINT_T2)

// PREFETCHNTA - Non-temporal prefetch
#define RAWRXD_PREFETCH_NTA(addr) \
    _mm_prefetch(reinterpret_cast<const char*>(addr), _MM_HINT_NTA)

// MOVNTPS - Non-temporal store
#define RAWRXD_STREAM_STORE(dest, src) \
    _mm512_stream_ps(dest, src)

// SFENCE - Ensure stores are globally visible
#define RAWRXD_STORE_FENCE() \
    _mm_sfence()

//=============================================================================
// Performance Monitoring
// Track prefetch effectiveness
//=============================================================================
struct PrefetchMetrics {
    std::atomic<uint64_t> prefetchesIssued{0};
    std::atomic<uint64_t> prefetchesUseful{0};
    std::atomic<uint64_t> cacheMissesAvoided{0};
    std::atomic<uint64_t> computationCycles{0};
    std::atomic<uint64_t> memoryWaitCycles{0};
    
    double GetPrefetchEfficiency() const {
        uint64_t issued = prefetchesIssued.load();
        return issued > 0 ? static_cast<double>(prefetchesUseful.load()) / issued : 0.0;
    }
    
    void Reset();
    std::string GetReport() const;
};

// Global metrics access
PrefetchMetrics& GetGlobalPrefetchMetrics();
void ResetPrefetchMetrics();

} // namespace Memory
} // namespace RawrXD
