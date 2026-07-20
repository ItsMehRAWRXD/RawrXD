// ============================================================================
// VAL-032: Tree Attention Bridge Implementation
// ============================================================================

#include "tree_attention_bridge.hpp"
#include <cstring>
#include <intrin.h>
#include <stdexcept>

namespace rxd {
namespace inference {

// ============================================================================
// Constructor / Destructor
// ============================================================================
TreeAttentionBridge::TreeAttentionBridge() = default;
TreeAttentionBridge::~TreeAttentionBridge() = default;

// ============================================================================
// Initialize
// ============================================================================
bool TreeAttentionBridge::Initialize(void* kvCacheBase, size_t kvCacheSize) {
    if (!kvCacheBase || kvCacheSize == 0) {
        return false;
    }
    
    // Verify 64-byte alignment
    if (reinterpret_cast<uintptr_t>(kvCacheBase) % 64 != 0) {
        return false;
    }
    
    kvCacheBase_ = kvCacheBase;
    kvCacheSize_ = kvCacheSize;
    initialized_ = true;
    
    return true;
}

// ============================================================================
// Verify Batch 4x4
// ============================================================================
TreeVerificationResult TreeAttentionBridge::VerifyBatch4x4(
    const float* query,
    const float* keyCache,
    const float* treeMask,
    const float* draftProbs,
    float* outputProbs
) {
    TreeVerificationResult result = {};
    
    if (!initialized_) {
        return result;
    }
    
    // Verify alignment (critical for AVX-512)
    auto isAligned64 = [](const void* ptr) {
        return reinterpret_cast<uintptr_t>(ptr) % 64 == 0;
    };
    
    if (!isAligned64(query) || !isAligned64(keyCache) ||
        !isAligned64(treeMask) || !isAligned64(draftProbs) ||
        !isAligned64(outputProbs)) {
        // Handle misalignment - could copy to aligned buffer
        return result;
    }
    
    // Serialize pipeline before measurement
    CycleCounter::Serialize();
    uint64_t startCycles = CycleCounter::ReadTSC();
    
    // Call MASM kernel
    // Note: In production, this calls the actual MASM procedure
    // For now, we use intrinsics as a reference implementation
    
    // Load query vectors (4 ZMM registers = 64 floats)
    __m512 q0 = _mm512_load_ps(query + 0);
    __m512 q1 = _mm512_load_ps(query + 16);
    __m512 q2 = _mm512_load_ps(query + 32);
    __m512 q3 = _mm512_load_ps(query + 48);
    
    // Compute dot products for 16 candidates
    // Each candidate has 64 floats (4 ZMM registers)
    __m512 scores[16];
    
    for (int i = 0; i < 16; i++) {
        const float* kPtr = keyCache + (i * 64);
        
        __m512 k0 = _mm512_load_ps(kPtr + 0);
        __m512 k1 = _mm512_load_ps(kPtr + 16);
        __m512 k2 = _mm512_load_ps(kPtr + 32);
        __m512 k3 = _mm512_load_ps(kPtr + 48);
        
        // Element-wise multiply and sum
        __m512 mul0 = _mm512_mul_ps(q0, k0);
        __m512 mul1 = _mm512_mul_ps(q1, k1);
        __m512 mul2 = _mm512_mul_ps(q2, k2);
        __m512 mul3 = _mm512_mul_ps(q3, k3);
        
        // Horizontal sum using reduce
        __m512 sum01 = _mm512_add_ps(mul0, mul1);
        __m512 sum23 = _mm512_add_ps(mul2, mul3);
        __m512 sumAll = _mm512_add_ps(sum01, sum23);
        
        // Store score (broadcast to all elements for simplicity)
        scores[i] = _mm512_set1_ps(_mm512_reduce_add_ps(sumAll));
    }
    
    // Apply tree mask (add -INF for invalid branches)
    __m512 treeMaskVec = _mm512_load_ps(treeMask);
    for (int i = 0; i < 16; i++) {
        scores[i] = _mm512_add_ps(scores[i], _mm512_set1_ps(treeMask[i]));
    }
    
    // Softmax computation
    // Find max for numerical stability
    __m512 maxVal = scores[0];
    for (int i = 1; i < 16; i++) {
        maxVal = _mm512_max_ps(maxVal, scores[i]);
    }
    
    // Subtract max and compute exp
    __m512 expScores[16];
    float maxScalar = _mm512_cvtss_f32(maxVal);
    
    for (int i = 0; i < 16; i++) {
        float score = _mm512_cvtss_f32(scores[i]) - maxScalar;
        // Fast exp approximation
        float expScore = std::exp(score);
        expScores[i] = _mm512_set1_ps(expScore);
        result.verifiedProbs[i] = expScore;
    }
    
    // Compute sum of exp scores
    float sumExp = 0.0f;
    for (int i = 0; i < 16; i++) {
        sumExp += _mm512_cvtss_f32(expScores[i]);
    }
    
    // Normalize and apply acceptance threshold
    const float threshold = 0.6f;
    uint64_t acceptanceMask = 0;
    
    for (int i = 0; i < 16; i++) {
        result.verifiedProbs[i] /= sumExp;
        
        // Acceptance: target_prob >= draft_prob * threshold
        float draftProb = draftProbs[i];
        if (result.verifiedProbs[i] >= draftProb * threshold) {
            acceptanceMask |= (1ULL << i);
        }
    }
    
    // Store results
    result.acceptanceMask = acceptanceMask;
    result.rejectionMask = ~acceptanceMask & 0xFFFF;
    result.acceptedCount = static_cast<uint32_t>(_mm_popcnt_u64(acceptanceMask));
    
    // Serialize and measure end
    CycleCounter::Serialize();
    uint64_t endCycles = CycleCounter::ReadTSC();
    
    lastCycleCount_ = endCycles - startCycles;
    result.cycleCount = lastCycleCount_;
    
    // Store output probabilities (masked)
    for (int i = 0; i < 16; i++) {
        if (acceptanceMask & (1ULL << i)) {
            outputProbs[i] = result.verifiedProbs[i];
        } else {
            outputProbs[i] = 0.0f;
        }
    }
    
    return result;
}

// ============================================================================
// Check AVX-512 Availability
// ============================================================================
bool TreeAttentionBridge::IsAVX512Available() {
    int cpuInfo[4] = {0};
    
    // Check for AVX-512 Foundation (bit 16 of EBX)
    __cpuid(cpuInfo, 7);
    bool avx512f = (cpuInfo[1] & (1 << 16)) != 0;
    
    // Check for AVX-512 DQ (bit 17 of EBX)
    bool avx512dq = (cpuInfo[1] & (1 << 17)) != 0;
    
    // Check for AVX-512 VL (bit 31 of EBX)
    bool avx512vl = (cpuInfo[1] & (1 << 31)) != 0;
    
    return avx512f && avx512dq && avx512vl;
}

} // namespace inference
} // namespace rxd
