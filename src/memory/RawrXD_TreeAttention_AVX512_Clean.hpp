#pragma once
#include "RawrXD_TreeAttention.hpp"
#include <cstdint>
#include <vector>
#include <intrin.h>

// ═══════════════════════════════════════════════════════════════════════════════
// VAL-032 AVX-512 Assembly Kernel Interface (Clean Version)
// ═══════════════════════════════════════════════════════════════════════════════

namespace RawrXD {

// External Assembly Functions
extern "C" {
    void TreeAttention_AVX512(
        const float* Q,
        const float* K,
        const float* V,
        float* output,
        const uint8_t* tree_mask,
        uint32_t num_nodes,
        uint32_t head_dim
    );

    void TreeAttention_ScoreBatch(
        const float* Q,
        const float* K,
        float* scores,
        const uint8_t* tree_mask,
        uint32_t num_q,
        uint32_t num_k,
        uint32_t head_dim
    );

    void TreeAttention_OnlineSoftmax(
        const float* scores,
        float* output,
        const uint8_t* tree_mask,
        uint32_t length
    );

    void TreeAttention_AVX512_ApplyMask(
        float* attn_scores,
        const uint8_t* tree_mask,
        uint32_t num_nodes,
        uint32_t head_dim
    );

    uint32_t TreeAttention_AVX512_VerifyBatch(
        const uint32_t* draft_tokens,
        const uint32_t* model_tokens,
        uint32_t num_tokens,
        uint32_t vocab_size,
        uint8_t* results
    );

    void TreeAttention_AVX512_Forward(
        const float* Q,
        const float* K,
        const float* V,
        float* output,
        const uint8_t* tree_mask,
        uint32_t num_nodes,
        uint32_t head_dim
    );
}

// AVX-512 Tree Attention Kernel Wrapper
class TreeAttentionKernelAVX512 {
public:
    struct Config {
        uint32_t headDim = 128;
        uint32_t blockSizeM = 64;
        uint32_t blockSizeN = 64;
    };

    explicit TreeAttentionKernelAVX512(const Config& cfg = {}) : config_(cfg) {}

    void Forward(
        const float* Q,
        const float* K,
        const float* V,
        float* output,
        const TreeBranch* branches,
        uint32_t numBranches,
        uint32_t headDim = 128
    ) {
        printf("  [C++] BuildMaskFromBranches starting...\n");
        BuildMaskFromBranches(branches, numBranches);
        printf("  [C++] BuildMaskFromBranches done, maskBuffer size=%zu\n", maskBuffer_.size());
        printf("  [C++] Calling TreeAttention_AVX512...\n");
        TreeAttention_AVX512(Q, K, V, output, maskBuffer_.data(), numBranches, headDim);
        printf("  [C++] TreeAttention_AVX512 returned\n");
    }

    void ComputeScores(
        const float* Q,
        const float* K,
        float* scores,
        const TreeBranch* branches,
        uint32_t numQ,
        uint32_t numK,
        uint32_t headDim
    ) {
        BuildMaskFromBranches(branches, numQ);
        TreeAttention_ScoreBatch(Q, K, scores, maskBuffer_.data(), numQ, numK, headDim);
    }

    void Softmax(
        const float* scores,
        float* output,
        const TreeBranch* branches,
        uint32_t length
    ) {
        BuildMaskFromBranches(branches, length);
        TreeAttention_OnlineSoftmax(scores, output, maskBuffer_.data(), length);
    }

    static bool IsSupported() {
        int cpuInfo[4];
        __cpuid(cpuInfo, 7);
        return (cpuInfo[1] & (1 << 16)) != 0;
    }

    const Config& GetConfig() const { return config_; }

private:
    Config config_;
    std::vector<uint8_t> maskBuffer_;

    void BuildMaskFromBranches(const TreeBranch* branches, uint32_t count) {
        maskBuffer_.resize(count * count);
        for (uint32_t i = 0; i < count; i++) {
            for (uint32_t j = 0; j < count; j++) {
                maskBuffer_[i * count + j] = CanAttend(branches, count, i, j) ? 1 : 0;
            }
        }
    }

    bool CanAttend(const TreeBranch* branches, uint32_t count, uint32_t from, uint32_t to) {
        if (from >= count || to >= count) return false;
        if (from == to) return true;
        
        uint32_t current = from;
        while (current != 0xFFFFFFFF && current < count) {
            if (branches[current].parentIdx == to) return true;
            current = branches[current].parentIdx;
        }
        
        // Siblings at same depth
        if (branches[from].depth == branches[to].depth &&
            branches[from].parentIdx == branches[to].parentIdx) {
            return true;
        }
        
        return false;
    }
};

} // namespace RawrXD
