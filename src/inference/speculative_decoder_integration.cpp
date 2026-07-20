// ============================================================================
// VAL-032: Speculative Decoder Integration Layer
// 
// Bridges the MASM kernel with the C++ SpeculativeDecoder class
// Implements the "Close-Loop" pipeline with B008 residency integration
// ============================================================================

#include "speculative_decoder.hpp"
#include "../memory/numa_fabric.hpp"
#include <immintrin.h>
#include <Windows.h>

namespace rawrxd {

// ============================================================================
// External MASM Kernel
// ============================================================================
extern "C" {
    // Tree verification kernel - returns rejection mask
    // RCX = Q_ptr, RDX = K_ptr, R8 = TreeMask_ptr, R9 = Output_probs
    // [RSP+40] = num_candidates
    uint64_t TreeVerify_Batch_4x4(
        const float* Q,
        const float* K,
        const uint8_t* treeMask,
        float* outputProbs,
        uint32_t numCandidates
    );
    
    // KV cache invalidation kernel
    // RCX = KV_ptr, RDX = rejection_mask, R8 = entry_size
    void KVCache_Invalidate_Masked(
        void* kvCache,
        uint64_t rejectionMask,
        size_t entrySize
    );
    
    // Feature detection
    bool TreeAttention_HasAVX512();
}

// ============================================================================
// Cycle Counter (for performance telemetry)
// ============================================================================
inline uint64_t ReadTSC() {
    _mm_lfence();
    uint64_t tsc = __rdtsc();
    _mm_lfence();
    return tsc;
}

// ============================================================================
// SpeculativeDecoder Implementation
// ============================================================================

SpeculativeDecoder::SpeculativeDecoder(
    ILanguageModel* draftModel,
    ILanguageModel* targetModel,
    ResidencyPlanner* residencyPlanner
) : draftModel_(draftModel),
    targetModel_(targetModel),
    residencyPlanner_(residencyPlanner),
    useAVX512_(TreeAttention_HasAVX512()),
    verificationCount_(0),
    acceptanceCount_(0)
{
    // Allocate aligned buffers for kernel
    Q_buffer_ = static_cast<float*>(_aligned_malloc(64 * sizeof(float), 64));
    K_buffer_ = static_cast<float*>(_aligned_malloc(16 * 64 * sizeof(float), 64));
    output_buffer_ = static_cast<float*>(_aligned_malloc(16 * sizeof(float), 64));
    treeMask_buffer_ = static_cast<uint8_t*>(_aligned_malloc(16, 64));
    
    if (!Q_buffer_ || !K_buffer_ || !output_buffer_ || !treeMask_buffer_) {
        throw std::runtime_error("Failed to allocate aligned buffers");
    }
}

SpeculativeDecoder::~SpeculativeDecoder() {
    _aligned_free(Q_buffer_);
    _aligned_free(K_buffer_);
    _aligned_free(output_buffer_);
    _aligned_free(treeMask_buffer_);
}

// ============================================================================
// ProcessVerification - The "Close-Loop" Pipeline
// ============================================================================

void SpeculativeDecoder::ProcessVerification(
    const float* logits,
    const uint32_t* draftTokens,
    uint32_t numTokens
) {
    if (!useAVX512_ || numTokens != 16) {
        // Fallback to reference implementation
        ProcessVerificationReference(logits, draftTokens, numTokens);
        return;
    }
    
    // Phase 1: Prefetch draft tensors (B008 residency)
    if (residencyPlanner_) {
        residencyPlanner_->PrefetchDraftTensors(draftTokens, numTokens);
    }
    
    // Phase 2: Prepare aligned buffers
    PrepareKernelBuffers(logits, draftTokens, numTokens);
    
    // Phase 3: Invoke AVX-512 kernel with cycle timing
    uint64_t startCycles = ReadTSC();
    
    uint64_t rejectionMask = TreeVerify_Batch_4x4(
        Q_buffer_,
        K_buffer_,
        treeMask_buffer_,
        output_buffer_,
        numTokens
    );
    
    uint64_t kernelCycles = ReadTSC() - startCycles;
    verificationCount_++;
    
    // Phase 4: Immediate branchless invalidation (if any rejected)
    if (rejectionMask != 0) {
        // Invert to get acceptance mask
        uint64_t acceptanceMask = ~rejectionMask & 0xFFFF;
        
        // Immediate KV cache invalidation
        if (residencyPlanner_) {
            residencyPlanner_->InvalidateRejectedKV(rejectionMask);
        }
        
        // Branchless rollback
        scheduler_.Rollback(rejectionMask);
        
        // Update acceptance stats
        acceptanceCount_ += __popcnt16(static_cast<uint16_t>(acceptanceMask));
    } else {
        // Full acceptance
        scheduler_.CommitAccepted();
        acceptanceCount_ += numTokens;
    }
    
    // Phase 5: Telemetry (optional, off hot path)
    if ((verificationCount_ & 0xFF) == 0) {
        // Log every 256 verifications
        LogTelemetry(kernelCycles, rejectionMask);
    }
}

// ============================================================================
// Helper: Prepare aligned buffers for kernel
// ============================================================================

void SpeculativeDecoder::PrepareKernelBuffers(
    const float* logits,
    const uint32_t* draftTokens,
    uint32_t numTokens
) {
    // Copy Q vector (query) - first 64 floats from logits
    memcpy(Q_buffer_, logits, 64 * sizeof(float));
    
    // Copy K vectors for each candidate
    // In production: fetch from KV cache based on draftTokens
    for (uint32_t i = 0; i < numTokens; i++) {
        // Simplified: use logits as K for now
        // Real implementation: lookup KV cache by token ID
        const float* kVec = logits + (i % 4) * 64; // Rotate through logits
        memcpy(K_buffer_ + i * 64, kVec, 64 * sizeof(float));
    }
    
    // Build tree mask (all valid initially)
    memset(treeMask_buffer_, 0xFF, numTokens);
    
    // Clear output buffer
    memset(output_buffer_, 0, numTokens * sizeof(float));
}

// ============================================================================
// Helper: Reference implementation (fallback)
// ============================================================================

void SpeculativeDecoder::ProcessVerificationReference(
    const float* logits,
    const uint32_t* draftTokens,
    uint32_t numTokens
) {
    // Simple sequential verification (no AVX-512)
    for (uint32_t i = 0; i < numTokens; i++) {
        // Compute acceptance probability
        float maxLogit = logits[0];
        for (int j = 1; j < 32000; j++) {
            if (logits[j] > maxLogit) maxLogit = logits[j];
        }
        
        float prob = std::exp(logits[draftTokens[i]] - maxLogit);
        
        // Simple threshold acceptance
        if (prob < 0.5f) {
            scheduler_.Rollback(1ULL << i);
        }
    }
    
    scheduler_.CommitAccepted();
}

// ============================================================================
// Helper: Telemetry logging
// ============================================================================

void SpeculativeDecoder::LogTelemetry(uint64_t kernelCycles, uint64_t rejectionMask) {
    // Calculate acceptance rate
    float acceptanceRate = (verificationCount_ > 0) 
        ? static_cast<float>(acceptanceCount_) / (verificationCount_ * 16.0f)
        : 0.0f;
    
    // Estimate TPS
    float estimatedTPS = 3.5e9f / static_cast<float>(kernelCycles);
    
    // Log to telemetry system (non-blocking)
    // In production: write to circular buffer or shared memory
    (void)rejectionMask; // Unused in this simplified version
}

// ============================================================================
// Scheduler Integration
// ============================================================================

void SpeculativeDecoder::Scheduler::Rollback(uint64_t rejectionMask) {
    // Branchless rollback using mask
    // Mark rejected positions as invalid in token stream
    for (int i = 0; i < 16; i++) {
        if ((rejectionMask >> i) & 1) {
            // Position i is rejected
            acceptedTokens_[i] = false;
        }
    }
}

void SpeculativeDecoder::Scheduler::CommitAccepted() {
    // All tokens accepted - commit to output stream
    for (int i = 0; i < 16; i++) {
        acceptedTokens_[i] = true;
    }
}

// ============================================================================
// ResidencyPlanner Integration (B008)
// ============================================================================

void ResidencyPlanner::PrefetchDraftTensors(const uint32_t* tokens, uint32_t count) {
    // NUMA-aware prefetch
    // Use prefetcht0 hints for L1 cache
    for (uint32_t i = 0; i < count; i++) {
        // Prefetch weight tensors for each token
        // In production: map token IDs to weight addresses
        _mm_prefetch(reinterpret_cast<const char*>(tokens + i), _MM_HINT_T0);
    }
}

void ResidencyPlanner::InvalidateRejectedKV(uint64_t rejectionMask) {
    // Immediate branchless invalidation
    // This maps to the MASM vmovdqu8 {k5} logic
    
    // For each rejected position
    for (int i = 0; i < 16; i++) {
        if ((rejectionMask >> i) & 1) {
            // Mark KV tile as dirty/available
            kvTiles_[i].status = KVTile::DIRTY;
        }
    }
}

void ResidencyPlanner::PromoteAcceptedKV(uint64_t acceptanceMask) {
    // Promote accepted KV entries to hot tier
    for (int i = 0; i < 16; i++) {
        if ((acceptanceMask >> i) & 1) {
            kvTiles_[i].status = KVTile::HOT;
        }
    }
}

} // namespace rawrxd
