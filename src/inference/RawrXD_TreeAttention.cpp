#include "RawrXD_TreeAttention.hpp"
#include <cstring>
#include <algorithm>
#include <cmath>
#include <Windows.h>

namespace RawrXD {
namespace Inference {

// ============================================================================
// Tree Causal Mask Implementation
// ============================================================================

TreeCausalMask::TreeCausalMask()
    : stride_(0) {
}

TreeCausalMask::~TreeCausalMask() = default;

bool TreeCausalMask::Build(const std::array<TreeNode, TreeConfig::MAX_NODES>& nodes,
                           uint32_t activeNodeCount) {
    if (activeNodeCount == 0 || activeNodeCount > TreeConfig::MAX_NODES) {
        return false;
    }
    
    stride_ = activeNodeCount;
    maskBuffer_.resize(activeNodeCount * stride_, 0);
    
    // Build mask: node i can attend to node j if j is ancestor of i
    for (uint32_t i = 0; i < activeNodeCount; i++) {
        // Each node can always attend to itself
        maskBuffer_[i * stride_ + i] = 1;
        
        // Walk up the tree and mark ancestors
        uint32_t current = i;
        while (current != 0xFFFFFFFF && nodes[current].parentIdx != 0xFFFFFFFF) {
            uint32_t parent = nodes[current].parentIdx;
            if (parent < activeNodeCount) {
                maskBuffer_[i * stride_ + parent] = 1;
            }
            current = parent;
        }
        
        // Root node (0) is always an ancestor
        if (i > 0) {
            maskBuffer_[i * stride_ + 0] = 1;
        }
    }
    
    return true;
}

bool TreeCausalMask::CanAttend(uint32_t fromNode, uint32_t toNode) const {
    if (fromNode >= stride_ || toNode >= stride_) {
        return false;
    }
    return maskBuffer_[fromNode * stride_ + toNode] != 0;
}

// ============================================================================
// Tree Attention Kernel Implementation
// ============================================================================

TreeAttentionKernel::TreeAttentionKernel()
    : initialized_(false)
    , tileSizeM_(64)
    , tileSizeN_(64)
    , tileSizeK_(32) {
}

TreeAttentionKernel::~TreeAttentionKernel() = default;

bool TreeAttentionKernel::Initialize(uint32_t tileSizeM, uint32_t tileSizeN, uint32_t tileSizeK) {
    tileSizeM_ = tileSizeM;
    tileSizeN_ = tileSizeN;
    tileSizeK_ = tileSizeK;
    initialized_ = true;
    return true;
}

bool TreeAttentionKernel::Forward(const TreeAttentionParams& params) {
    if (!initialized_) {
        return false;
    }
    
    auto startTime = GetTickCount64();
    
    // Validate parameters
    if (!params.query || !params.key || !params.value || !params.output) {
        return false;
    }
    
    if (params.numNodes == 0 || params.numNodes > TreeConfig::MAX_NODES) {
        return false;
    }
    
    // Launch kernel (or reference implementation)
    bool success = LaunchKernel(params);
    
    // Update statistics
    auto elapsedMs = GetTickCount64() - startTime;
    kernelInvocations_++;
    tokensProcessed_ += params.numNodes;
    totalKernelTimeMs_ += elapsedMs;
    
    return success;
}

uint32_t TreeAttentionKernel::VerifyDraftTokens(const TreeAttentionParams& params,
                                               const float* draftLogits,
                                               const float* targetLogits,
                                               float temperature,
                                               uint32_t* acceptedTokenIds,
                                               uint32_t* acceptedCount) {
    if (!initialized_ || !draftLogits || !targetLogits || !acceptedTokenIds || !acceptedCount) {
        return 0;
    }
    
    *acceptedCount = 0;
    
    // Simple verification: accept if target_prob >= draft_prob
    // In production: use more sophisticated rejection sampling
    for (uint32_t i = 0; i < params.numNodes; i++) {
        // Find max logit for draft and target
        // Simplified: just compare first element for now
        float draftProb = std::exp(draftLogits[i] / temperature);
        float targetProb = std::exp(targetLogits[i] / temperature);
        
        // Normalize (simplified)
        draftProb = std::min(draftProb, 1.0f);
        targetProb = std::min(targetProb, 1.0f);
        
        // Acceptance criterion
        if (targetProb >= draftProb || (targetProb / draftProb) > 0.5f) {
            acceptedTokenIds[*acceptedCount] = i;
            (*acceptedCount)++;
        }
    }
    
    tokensAccepted_ += *acceptedCount;
    return *acceptedCount;
}

TreeAttentionKernel::Stats TreeAttentionKernel::GetStats() const {
    Stats stats;
    stats.kernelInvocations = kernelInvocations_;
    stats.tokensProcessed = tokensProcessed_;
    stats.tokensAccepted = tokensAccepted_;
    stats.avgAcceptanceRate = tokensProcessed_ > 0 ? 
        static_cast<double>(tokensAccepted_) / tokensProcessed_ : 0.0;
    stats.avgKernelTimeMs = kernelInvocations_ > 0 ? 
        totalKernelTimeMs_ / kernelInvocations_ : 0.0;
    return stats;
}

bool TreeAttentionKernel::LaunchKernel(const TreeAttentionParams& params) {
    // Reference implementation (not optimized)
    // Production would use AVX-512 assembly
    
    const uint32_t numNodes = params.numNodes;
    const uint32_t headDim = params.headDim;
    const uint32_t numHeads = params.numHeads;
    const float scale = params.softmaxScale;
    
    // Temporary buffers
    std::vector<float> scores(numNodes * numNodes);
    std::vector<float> softmaxed(numNodes * numNodes);
    
    // For each head
    for (uint32_t h = 0; h < numHeads; h++) {
        const float* qHead = params.query + h * numNodes * headDim;
        const float* kHead = params.key + h * numNodes * headDim;
        const float* vHead = params.value + h * numNodes * headDim;
        float* outHead = params.output + h * numNodes * headDim;
        
        // Compute Q @ K^T
        for (uint32_t i = 0; i < numNodes; i++) {
            for (uint32_t j = 0; j < numNodes; j++) {
                float dot = 0.0f;
                for (uint32_t k = 0; k < headDim; k++) {
                    dot += qHead[i * headDim + k] * kHead[j * headDim + k];
                }
                scores[i * numNodes + j] = dot * scale;
            }
        }
        
        // Apply causal mask and softmax
        for (uint32_t i = 0; i < numNodes; i++) {
            // Find max for numerical stability
            float maxScore = -1e30f;
            for (uint32_t j = 0; j <= i; j++) {  // Causal: only attend to previous
                if (params.causalMask == nullptr || 
                    params.causalMask[i * numNodes + j]) {
                    maxScore = std::max(maxScore, scores[i * numNodes + j]);
                }
            }
            
            // Compute softmax
            float sum = 0.0f;
            for (uint32_t j = 0; j <= i; j++) {
                if (params.causalMask == nullptr || 
                    params.causalMask[i * numNodes + j]) {
                    softmaxed[i * numNodes + j] = std::exp(scores[i * numNodes + j] - maxScore);
                    sum += softmaxed[i * numNodes + j];
                } else {
                    softmaxed[i * numNodes + j] = 0.0f;
                }
            }
            
            // Normalize
            for (uint32_t j = 0; j <= i; j++) {
                softmaxed[i * numNodes + j] /= sum;
            }
        }
        
        // Compute softmaxed @ V
        for (uint32_t i = 0; i < numNodes; i++) {
            for (uint32_t k = 0; k < headDim; k++) {
                float sum = 0.0f;
                for (uint32_t j = 0; j <= i; j++) {
                    sum += softmaxed[i * numNodes + j] * vHead[j * headDim + k];
                }
                outHead[i * headDim + k] = sum;
            }
        }
    }
    
    return true;
}

bool TreeAttentionKernel::ComputeSoftmax(const float* scores, float* probs,
                                        uint32_t rows, uint32_t cols) {
    for (uint32_t i = 0; i < rows; i++) {
        // Find max
        float maxVal = scores[i * cols];
        for (uint32_t j = 1; j < cols; j++) {
            maxVal = std::max(maxVal, scores[i * cols + j]);
        }
        
        // Compute exp and sum
        float sum = 0.0f;
        for (uint32_t j = 0; j < cols; j++) {
            probs[i * cols + j] = std::exp(scores[i * cols + j] - maxVal);
            sum += probs[i * cols + j];
        }
        
        // Normalize
        for (uint32_t j = 0; j < cols; j++) {
            probs[i * cols + j] /= sum;
        }
    }
    return true;
}

// ============================================================================
// Utility Functions
// ============================================================================

uint32_t BuildBalancedTree(const std::vector<std::vector<uint32_t>>& draftTokens,
                          std::array<TreeNode, TreeConfig::MAX_NODES>& treeNodes) {
    uint32_t nodeCount = 0;
    
    // Root node
    treeNodes[nodeCount].tokenId = 0;  // Placeholder
    treeNodes[nodeCount].parentIdx = 0xFFFFFFFF;
    treeNodes[nodeCount].depth = 0;
    treeNodes[nodeCount].cumulativeScore = 1.0f;
    treeNodes[nodeCount].accepted = false;
    nodeCount++;
    
    // Build tree level by level
    for (size_t depth = 0; depth < draftTokens.size() && depth < TreeConfig::DEPTH; depth++) {
        const auto& levelTokens = draftTokens[depth];
        uint32_t parentStart = (depth == 0) ? 0 : (1 << (2 * depth)) - 1;
        uint32_t parentEnd = nodeCount;
        
        for (uint32_t parentIdx = parentStart; parentIdx < parentEnd && parentIdx < nodeCount; parentIdx++) {
            for (size_t i = 0; i < TreeConfig::BRANCHING_FACTOR && i < levelTokens.size(); i++) {
                if (nodeCount >= TreeConfig::MAX_NODES) break;
                
                treeNodes[nodeCount].tokenId = levelTokens[i % levelTokens.size()];
                treeNodes[nodeCount].parentIdx = parentIdx;
                treeNodes[nodeCount].depth = static_cast<uint32_t>(depth + 1);
                treeNodes[nodeCount].cumulativeScore = treeNodes[parentIdx].cumulativeScore * 0.9f;
                treeNodes[nodeCount].accepted = false;
                nodeCount++;
            }
        }
    }
    
    return nodeCount;
}

TreeStats CalculateTreeStats(const std::array<TreeNode, TreeConfig::MAX_NODES>& nodes,
                            uint32_t activeCount) {
    TreeStats stats;
    stats.totalNodes = activeCount;
    stats.leafNodes = 0;
    stats.maxDepth = 0;
    stats.avgBranchingFactor = 0.0f;
    stats.memoryFootprintKB = (activeCount * sizeof(TreeNode)) / 1024;
    
    uint32_t totalChildren = 0;
    uint32_t nonLeafNodes = 0;
    
    for (uint32_t i = 0; i < activeCount; i++) {
        stats.maxDepth = std::max(stats.maxDepth, nodes[i].depth);
        
        // Count children
        uint32_t children = 0;
        for (uint32_t j = 0; j < activeCount; j++) {
            if (nodes[j].parentIdx == i) {
                children++;
            }
        }
        
        if (children == 0) {
            stats.leafNodes++;
        } else {
            totalChildren += children;
            nonLeafNodes++;
        }
    }
    
    if (nonLeafNodes > 0) {
        stats.avgBranchingFactor = static_cast<float>(totalChildren) / nonLeafNodes;
    }
    
    return stats;
}

} // namespace Inference
} // namespace RawrXD
