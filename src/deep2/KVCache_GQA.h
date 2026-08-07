// =============================================================================
// Blocker #5: KVCache with Grouped Query Attention (GQA) support
// Handles numHeads != numKVHeads by replicating KV heads.
// =============================================================================

#pragma once
#include <cstdint>
#include <cstring>
#include <vector>

class KVCache {
public:
    KVCache()
        : numLayers_(0)
        , numHeads_(0)
        , numKVHeads_(0)
        , headDim_(0)
        , maxSeqLen_(0)
        , currentLen_(0)
    {}

    bool init(int numLayers, int numHeads, int numKVHeads, int headDim, int maxSeqLen) {
        // Validate GQA ratio
        if (numHeads <= 0 || numKVHeads <= 0 || headDim <= 0 || maxSeqLen <= 0) {
            return false;
        }
        if (numHeads % numKVHeads != 0) {
            // GQA ratio must be integer
            return false;
        }

        numLayers_   = numLayers;
        numHeads_    = numHeads;
        numKVHeads_  = numKVHeads;
        headDim_     = headDim;
        maxSeqLen_   = maxSeqLen;
        currentLen_ = 0;
        gqaRatio_    = numHeads / numKVHeads;

        const int kvSize = numLayers * numKVHeads * headDim * maxSeqLen;
        kCache_.resize(kvSize, 0.0f);
        vCache_.resize(kvSize, 0.0f);

        return true;
    }

    // Store one position's K and V for all KV heads
    void store(int layer, int pos, const float* k, const float* v) {
        if (layer < 0 || layer >= numLayers_) return;
        if (pos < 0 || pos >= maxSeqLen_) return;

        const int offset = layer * numKVHeads_ * headDim_ * maxSeqLen_
                         + pos * headDim_;

        for (int h = 0; h < numKVHeads_; h++) {
            const int headOffset = offset + h * headDim_ * maxSeqLen_;
            std::memcpy(&kCache_[headOffset], k + h * headDim_, headDim_ * sizeof(float));
            std::memcpy(&vCache_[headOffset], v + h * headDim_, headDim_ * sizeof(float));
        }

        if (pos + 1 > currentLen_) {
            currentLen_ = pos + 1;
        }
    }

    // Attention with GQA: each Q head maps to a KV head via headIdx / gqaRatio_
    void attention(
        int layer,
        const float* q,       // [numHeads * headDim]
        float* out,            // [numHeads * headDim]
        float scale
    ) const {
        const int seqLen = currentLen_;
        if (seqLen <= 0) return;

        for (int qh = 0; qh < numHeads_; qh++) {
            const int kvh = qh / gqaRatio_;  // Map Q head to KV head
            const int qOffset = qh * headDim_;
            const int outOffset = qh * headDim_;
            const int kvHeadBase = layer * numKVHeads_ * headDim_ * maxSeqLen_
                                 + kvh * headDim_ * maxSeqLen_;

            // Compute attention scores
            std::vector<float> scores(seqLen);
            float maxScore = -1e30f;

            for (int t = 0; t < seqLen; t++) {
                float dot = 0.0f;
                for (int d = 0; d < headDim_; d++) {
                    dot += q[qOffset + d] * kCache_[kvHeadBase + t * headDim_ + d];
                }
                scores[t] = dot * scale;
                if (scores[t] > maxScore) maxScore = scores[t];
            }

            // Softmax
            float sum = 0.0f;
            for (int t = 0; t < seqLen; t++) {
                scores[t] = std::exp(scores[t] - maxScore);
                sum += scores[t];
            }
            float invSum = (sum > 0.0f) ? 1.0f / sum : 0.0f;

            // Weighted sum of V
            for (int d = 0; d < headDim_; d++) {
                out[outOffset + d] = 0.0f;
            }
            for (int t = 0; t < seqLen; t++) {
                const float w = scores[t] * invSum;
                for (int d = 0; d < headDim_; d++) {
                    out[outOffset + d] += w * vCache_[kvHeadBase + t * headDim_ + d];
                }
            }
        }
    }

    void reset() {
        currentLen_ = 0;
        std::fill(kCache_.begin(), kCache_.end(), 0.0f);
        std::fill(vCache_.begin(), vCache_.end(), 0.0f);
    }

    int currentLen() const { return currentLen_; }
    int maxSeqLen() const { return maxSeqLen_; }
    int numHeads() const { return numHeads_; }
    int numKVHeads() const { return numKVHeads_; }
    int gqaRatio() const { return gqaRatio_; }

private:
    int numLayers_;
    int numHeads_;
    int numKVHeads_;
    int headDim_;
    int maxSeqLen_;
    int currentLen_;
    int gqaRatio_;
    std::vector<float> kCache_;
    std::vector<float> vCache_;
};