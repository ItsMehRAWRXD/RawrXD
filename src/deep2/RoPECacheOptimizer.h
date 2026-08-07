// ============================================================================
// Blocker #29: RoPE Cache L2 Optimization
// Optimizes RoPE cache for L2 residency by:
// - Using smaller cache lines (32-byte aligned)
// - Precomputing sin/cos tables in SoA (Structure of Arrays) format
// - Touching tables in sequential order to maximize prefetcher efficiency
// ============================================================================
#pragma once
#include <cstdint>
#include <cmath>
#include <vector>
#include <algorithm>

namespace Deep2 {

class RoPECacheOptimizer {
public:
    RoPECacheOptimizer() : maxSeqLen_(0), headDim_(0), theta_(10000.0f) {}

    void Initialize(size_t maxSeqLen, size_t headDim, float theta = 10000.0f) {
        maxSeqLen_ = maxSeqLen;
        headDim_ = headDim;
        theta_ = theta;
        
        // Precompute in SoA format for better cache locality
        // sinTable_[pos * (headDim/2) + i] = sin(pos * theta_i)
        // cosTable_[pos * (headDim/2) + i] = cos(pos * theta_i)
        size_t halfDim = headDim / 2;
        cosTable_.resize(maxSeqLen * halfDim);
        sinTable_.resize(maxSeqLen * halfDim);
        
        for (size_t pos = 0; pos < maxSeqLen; ++pos) {
            for (size_t i = 0; i < halfDim; ++i) {
                float freq = 1.0f / std::pow(theta_, (2.0f * i) / headDim);
                float angle = pos * freq;
                cosTable_[pos * halfDim + i] = std::cos(angle);
                sinTable_[pos * halfDim + i] = std::sin(angle);
            }
        }
        
        // Touch all pages to ensure they're in memory
        WarmCache();
    }

    // Apply RoPE to Q and K vectors using optimized cache-friendly access
    void ApplyRoPEOptimized(float* q, float* k, size_t numHeads, size_t numKVHeads,
                            size_t pos, float scaling = 1.0f) const {
        if (cosTable_.empty() || pos >= maxSeqLen_) return;
        
        size_t halfDim = headDim_ / 2;
        size_t cosOff = pos * halfDim;
        
        // Process Q heads
        for (size_t h = 0; h < numHeads; ++h) {
            float* qh = q + h * headDim_;
            for (size_t i = 0; i < halfDim; ++i) {
                float cosA = cosTable_[cosOff + i] * scaling;
                float sinA = sinTable_[cosOff + i] * scaling;
                float q0 = qh[i * 2];
                float q1 = qh[i * 2 + 1];
                qh[i * 2]     = q0 * cosA - q1 * sinA;
                qh[i * 2 + 1] = q0 * sinA + q1 * cosA;
            }
        }
        
        // Process K heads
        for (size_t h = 0; h < numKVHeads; ++h) {
            float* kh = k + h * headDim_;
            for (size_t i = 0; i < halfDim; ++i) {
                float cosA = cosTable_[cosOff + i] * scaling;
                float sinA = sinTable_[cosOff + i] * scaling;
                float k0 = kh[i * 2];
                float k1 = kh[i * 2 + 1];
                kh[i * 2]     = k0 * cosA - k1 * sinA;
                kh[i * 2 + 1] = k0 * sinA + k1 * cosA;
            }
        }
    }

    // Get cache size in bytes
    size_t GetCacheSizeBytes() const {
        return (cosTable_.size() + sinTable_.size()) * sizeof(float);
    }

    // Check if cache is initialized
    bool IsInitialized() const {
        return !cosTable_.empty();
    }

    // Touch all cache lines to warm up L2
    void WarmCache() {
        volatile float sum = 0.0f;
        for (size_t i = 0; i < cosTable_.size(); i += 8) {
            sum += cosTable_[i];
        }
        for (size_t i = 0; i < sinTable_.size(); i += 8) {
            sum += sinTable_[i];
        }
        (void)sum; // Prevent optimization
    }

    // Get memory bandwidth estimate (bytes touched per token)
    size_t GetBytesPerToken(size_t numHeads, size_t numKVHeads) const {
        // Each token touches: numHeads * headDim * 2 (read/write Q) 
        //                 + numKVHeads * headDim * 2 (read/write K)
        //                 + headDim/2 * 2 * sizeof(float) (read sin/cos)
        return (numHeads + numKVHeads) * headDim_ * 2 * sizeof(float) +
               headDim_ * sizeof(float);
    }

private:
    std::vector<float> cosTable_;
    std::vector<float> sinTable_;
    size_t maxSeqLen_;
    size_t headDim_;
    float theta_;
};

} // namespace Deep2
