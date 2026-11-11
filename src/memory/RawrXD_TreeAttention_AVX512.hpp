#pragma once
#include "RawrXD_TreeAttention.hpp"
#include <cstdint>

// ═══════════════════════════════════════════════════════════════════════════════
// VAL-032 AVX-512 Assembly Kernel Interface
// ═══════════════════════════════════════════════════════════════════════════════
// C++ wrapper for the branchless AVX-512 Tree Attention assembly implementation.
// Provides seamless integration with the existing TreeAttention class.
// ═══════════════════════════════════════════════════════════════════════════════

namespace RawrXD {

// ═══════════════════════════════════════════════════════════════════════════════
// External Assembly Functions (from RawrXD_TreeAttention_AVX512.asm)
// ═══════════════════════════════════════════════════════════════════════════════
extern "C" {
    // Apply tree causal mask using k-mask registers (branchless)
    void TreeAttention_AVX512_ApplyMask(
        float* attn_scores,       // [num_nodes] attention scores
        const uint8_t* tree_mask, // [num_nodes] 1 = can attend, 0 = masked
        uint32_t num_nodes,       // Number of tree nodes
        uint32_t head_dim         // Head dimension (for alignment)
    );

    // Verify draft tokens against model output (branchless comparison)
    uint32_t TreeAttention_AVX512_VerifyBatch(
        const uint32_t* draft_tokens,   // [num_tokens] draft token IDs
        const uint32_t* model_tokens,   // [num_tokens] model predicted tokens
        uint32_t num_tokens,            // Number of tokens to verify
        uint32_t vocab_size,            // Vocabulary size
        uint8_t* results                // [num_tokens] output: 1 = accepted, 0 = rejected
    );

    // Main tree attention forward pass with online softmax
    void TreeAttention_AVX512_Forward(
        const float* Q,           // [num_nodes, head_dim] queries
        const float* K,           // [num_nodes, head_dim] keys
        const float* V,           // [num_nodes, head_dim] values
        float* output,            // [num_nodes, head_dim] output
        const uint8_t* tree_mask, // [num_nodes, num_nodes] causal mask
        uint32_t num_nodes,       // Number of nodes
        uint32_t head_dim         // Head dimension
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// AVX-512 Tree Attention Kernel Wrapper
// ═══════════════════════════════════════════════════════════════════════════════
class TreeAttentionKernelAVX512 : public TreeAttentionKernel {
public:
    explicit TreeAttentionKernelAVX512(const TreeAttentionConfig& cfg = {})
        : TreeAttentionKernel(cfg) {}

    // Override Forward with AVX-512 implementation
    void Forward(
        const float* Q,
        const float* K,
        const float* V,
        float* output,
        const TreeBranch* branches,
        uint32_t numBranches,
        uint32_t headDim = 128
    ) override {
        // Build tree mask from branches
        BuildMaskFromBranches(branches, numBranches);
        
        // Call assembly kernel
        TreeAttention_AVX512(
            Q, K, V, output,
            maskBuffer_.data(),
            numBranches,
            headDim
        );
    }

    // Fast path for score computation
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
        
        TreeAttention_ScoreBatch(
            Q, K, scores,
            maskBuffer_.data(),
            numQ, numK, headDim
        );
    }

    // Optimized softmax for tree attention
    void Softmax(
        const float* scores,
        float* output,
        const TreeBranch* branches,
        uint32_t length
    ) {
        BuildMaskFromBranches(branches, length);
        
        TreeAttention_OnlineSoftmax(
            scores, output,
            maskBuffer_.data(),
            length
        );
    }

    // Check if AVX-512 is available on this CPU
    static bool IsSupported() {
        #ifdef _MSC_VER
        int cpuInfo[4];
        __cpuid(cpuInfo, 7);
        // Check AVX-512F bit (bit 16 of EBX)
        return (cpuInfo[1] & (1 << 16)) != 0;
        #else
        // GCC/Clang
        return __builtin_cpu_supports("avx512f");
        #endif
    }

private:
    std::vector<uint8_t> maskBuffer_;

    void BuildMaskFromBranches(const TreeBranch* branches, uint32_t count) {
        maskBuffer_.resize(count * count);
        
        for (uint32_t i = 0; i < count; i++) {
            for (uint32_t j = 0; j < count; j++) {
                // Can node i attend to node j?
                maskBuffer_[i * count + j] = CanAttend(branches, count, i, j) ? 1 : 0;
            }
        }
    }

    bool CanAttend(const TreeBranch* branches, uint32_t count, uint32_t from, uint32_t to) {
        if (from >= count || to >= count) return false;
        
        // Can attend to self
        if (from == to) return true;
        
        // Can attend to ancestors
        uint32_t current = from;
        while (current != 0xFFFFFFFF && current < count) {
            if (branches[current].parentIdx == to) {
                return true; // 'to' is ancestor of 'from'
            }
            current = branches[current].parentIdx;
        }
        
        // Can attend to siblings at same depth
        if (branches[from].depth == branches[to].depth &&
            branches[from].parentIdx == branches[to].parentIdx) {
            return true;
        }
        
        return false;
    }
};

// ═══════════════════════════════════════════════════════════════════════════════
// Factory function to create optimal kernel
// ═══════════════════════════════════════════════════════════════════════════════
inline std::unique_ptr<TreeAttentionKernel> CreateTreeAttentionKernel(
    const TreeAttentionConfig& cfg = {}
) {
    if (TreeAttentionKernelAVX512::IsSupported()) {
        return std::make_unique<TreeAttentionKernelAVX512>(cfg);
    }
    // Fall back to scalar implementation
    return std::make_unique<TreeAttentionKernel>(cfg);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Performance Telemetry for AVX-512 Kernel
// ═══════════════════════════════════════════════════════════════════════════════
struct TreeAttentionPerfStats {
    uint64_t kernelCalls = 0;
    uint64_t totalCycles = 0;
    uint64_t nodesProcessed = 0;
    
    float GetAverageCyclesPerNode() const {
        return nodesProcessed > 0 ? 
            (float)totalCycles / nodesProcessed : 0.0f;
    }
};

// Global stats (thread-safe via TLS in production)
extern TreeAttentionPerfStats g_treeAttnStats;

// ═══════════════════════════════════════════════════════════════════════════════
// Integration with SpeculativeScheduler
// ═══════════════════════════════════════════════════════════════════════════════
class SpeculativeSchedulerAVX512 : public SpeculativeScheduler {
    std::unique_ptr<TreeAttentionKernelAVX512> kernel_;
    
public:
    explicit SpeculativeSchedulerAVX512(const Config& cfg = {})
        : SpeculativeScheduler(cfg) {
        if (TreeAttentionKernelAVX512::IsSupported()) {
            kernel_ = std::make_unique<TreeAttentionKernelAVX512>();
        }
    }
    
    bool HasAVX512() const { return kernel_ != nullptr; }
    
    // Override verification to use AVX-512 kernel
    TreeAttentionKernel::VerificationResult VerifyDraftTreeAVX512(
        const TreeBatch& batch,
        const float* modelLogits,
        uint32_t vocabSize
    ) {
        if (!kernel_) {
            // Fall back to base implementation
            return TreeAttentionKernel(GetConfig()).VerifyDraftTree(batch, modelLogits, vocabSize);
        }
        
        // AVX-512 optimized verification
        return kernel_->VerifyDraftTree(batch, modelLogits, vocabSize);
    }
};

} // namespace RawrXD
