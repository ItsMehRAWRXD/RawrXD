#pragma once

#include "../memory/RawrXD_FlashAttention_v2.hpp"
#include <cstdint>
#include <array>
#include <vector>

namespace RawrXD {
namespace Inference {

// ============================================================================
// VAL-032: Tree Attention Kernel
// 
// Implements batched tree verification for speculative decoding.
// Instead of verifying draft tokens sequentially, we batch them into
// a single attention pass with a tree-structured causal mask.
//
// Tree Structure: Fixed 4x4 (depth 4, branching factor 4)
// - Root: Current verified token
// - Level 1: 4 draft candidates
// - Level 2: 16 draft candidates (4 per parent)
// - Level 3: 64 draft candidates
// - Total: 84 tokens in single verification pass
// ============================================================================

// Tree configuration
struct TreeConfig {
    static constexpr uint32_t DEPTH = 4;           // Tree depth
    static constexpr uint32_t BRANCHING_FACTOR = 4; // Children per node
    static constexpr uint32_t MAX_NODES = 85;      // 1 + 4 + 16 + 64
    
    // Cache-friendly layout: nodes stored in breadth-first order
    // Node 0: Root
    // Nodes 1-4: Level 1
    // Nodes 5-20: Level 2
    // Nodes 21-84: Level 3
};

// Node metadata in tree
struct TreeNode {
    uint32_t tokenId;           // Draft token ID
    uint32_t parentIdx;         // Parent node index (0xFFFFFFFF for root)
    uint32_t depth;             // Depth in tree (0 = root)
    float cumulativeScore;      // Product of probabilities along path
    bool accepted;              // Verification result
    uint32_t pad;               // Padding to 24 bytes
};

// Causal mask for tree attention
// Each node can attend to:
// 1. All verified tokens (prefix)
// 2. Its ancestors in the tree
// 3. NOT its siblings or descendants
class TreeCausalMask {
public:
    TreeCausalMask();
    ~TreeCausalMask();
    
    // Build mask for current tree structure
    bool Build(const std::array<TreeNode, TreeConfig::MAX_NODES>& nodes,
               uint32_t activeNodeCount);
    
    // Get mask buffer for kernel
    const uint8_t* GetMaskBuffer() const { return maskBuffer_.data(); }
    size_t GetMaskSize() const { return maskBuffer_.size(); }
    
    // Check if node i can attend to node j
    bool CanAttend(uint32_t fromNode, uint32_t toNode) const;
    
private:
    // Mask stored as bit matrix: mask[i * stride + j] = 1 if i can attend to j
    std::vector<uint8_t> maskBuffer_;
    uint32_t stride_;
};

// ============================================================================
// Tree Attention Kernel
// 
// Extends FlashAttention with tree-structured causal masking.
// Processes all 84 draft tokens in parallel with O(1) memory bandwidth
// per token (thanks to FlashAttention's tiling).
// ============================================================================

struct TreeAttentionParams {
    // Input
    const float* query;           // [numNodes, headDim]
    const float* key;             // [numNodes + prefixLen, headDim]
    const float* value;           // [numNodes + prefixLen, headDim]
    const uint8_t* causalMask;    // [numNodes, numNodes + prefixLen]
    
    // Dimensions
    uint32_t numNodes;            // Active nodes in tree (<= 85)
    uint32_t prefixLen;           // Verified prefix length
    uint32_t numHeads;            // Number of attention heads
    uint32_t headDim;             // Head dimension (typically 64 or 128)
    
    // Output
    float* output;                // [numNodes, headDim]
    float* softmaxStats;          // [numNodes, numHeads] for debugging
    
    // Tuning
    float softmaxScale;           // Typically 1.0 / sqrt(headDim)
    bool useFP16;                 // Use FP16 for intermediate compute
};

class TreeAttentionKernel {
public:
    TreeAttentionKernel();
    ~TreeAttentionKernel();
    
    // Initialize kernel with tile sizes
    bool Initialize(uint32_t tileSizeM = 64,    // Query tiles
                   uint32_t tileSizeN = 64,     // KV tiles
                   uint32_t tileSizeK = 32);    // Head dim tiles
    
    // Execute tree attention
    // Returns: true on success, false on error
    bool Forward(const TreeAttentionParams& params);
    
    // Verify draft tokens against model predictions
    // Returns: number of accepted tokens (0 to numNodes)
    uint32_t VerifyDraftTokens(const TreeAttentionParams& params,
                              const float* draftLogits,    // [numNodes, vocabSize]
                              const float* targetLogits,   // [numNodes, vocabSize]
                              float temperature,
                              uint32_t* acceptedTokenIds,  // Output: accepted tokens
                              uint32_t* acceptedCount);    // Output: how many accepted
    
    // Statistics
    struct Stats {
        uint64_t kernelInvocations;
        uint64_t tokensProcessed;
        uint64_t tokensAccepted;
        double avgAcceptanceRate;
        double avgKernelTimeMs;
    };
    Stats GetStats() const;
    
private:
    bool initialized_;
    uint32_t tileSizeM_;
    uint32_t tileSizeN_;
    uint32_t tileSizeK_;
    
    // Statistics
    alignas(64) uint64_t kernelInvocations_{0};
    alignas(64) uint64_t tokensProcessed_{0};
    alignas(64) uint64_t tokensAccepted_{0};
    alignas(64) double totalKernelTimeMs_{0};
    
    // Internal implementation
    bool LaunchKernel(const TreeAttentionParams& params);
    bool ComputeSoftmax(const float* scores, float* probs, 
                       uint32_t rows, uint32_t cols);
};

// ============================================================================
// Optimized Tree Attention (Assembly)
// 
// x64 assembly implementation for maximum throughput.
// Uses AVX-512 if available, falls back to AVX2.
// ============================================================================

#ifdef __cplusplus
extern "C" {
#endif

// Assembly entry point
// RCX = params pointer
// RDX = thread ID
// R8 = num threads
// Returns: 0 on success
int TreeAttention_ASM(void* params, uint32_t threadId, uint32_t numThreads);

// Verify if AVX-512 is available
bool TreeAttention_HasAVX512();

// Get optimal thread count
uint32_t TreeAttention_GetOptimalThreads();

#ifdef __cplusplus
}
#endif

// ============================================================================
// Utility Functions
// ============================================================================

// Build a balanced 4x4 tree from draft tokens
// draftTokens: [depth][branchingFactor] array of candidate tokens
// treeNodes: output array of TreeNode structures
// Returns: number of nodes built (<= 85)
uint32_t BuildBalancedTree(
    const std::vector<std::vector<uint32_t>>& draftTokens,
    std::array<TreeNode, TreeConfig::MAX_NODES>& treeNodes);

// Calculate tree statistics
struct TreeStats {
    uint32_t totalNodes;
    uint32_t leafNodes;
    uint32_t maxDepth;
    float avgBranchingFactor;
    uint32_t memoryFootprintKB;
};
TreeStats CalculateTreeStats(const std::array<TreeNode, TreeConfig::MAX_NODES>& nodes,
                            uint32_t activeCount);

} // namespace Inference
} // namespace RawrXD
