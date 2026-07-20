#pragma once
#include "RawrXD_FlashAttention_v2.hpp"
#include "RawrXD_SpeculativeScheduler.hpp"
#include <cstdint>
#include <vector>
#include <memory>

// ═══════════════════════════════════════════════════════════════════════════════
// VAL-032 Phase 2: Tree-Aware Flash Attention
// ═══════════════════════════════════════════════════════════════════════════════
// Extends Flash Attention v2 to support tree-structured causal masks for
// speculative decoding verification. Transforms linear attention into
// DAG-based attention for parallel draft token verification.
// ═══════════════════════════════════════════════════════════════════════════════

namespace RawrXD {

// ═══════════════════════════════════════════════════════════════════════════════
// Tree Attention Configuration
// ═══════════════════════════════════════════════════════════════════════════════
struct TreeAttentionConfig {
    // Tree structure limits
    uint32_t maxNodes = 256;           // Max nodes in verification tree
    uint32_t maxDepth = 5;               // Max speculation depth
    uint32_t maxBranchingFactor = 4;     // Max branches per node
    
    // Performance tuning
    uint32_t blockSizeM = 64;          // Query block size (matches FlashAttn v2)
    uint32_t blockSizeN = 64;          // Key block size
    uint32_t blockSizeK = 32;          // Head dim block size
    
    // Memory layout
    bool useSharedPrefix = true;         // Share KV cache for common prefixes
    float sharedPrefixThreshold = 0.9f;  // Min similarity to share
};

// ═══════════════════════════════════════════════════════════════════════════════
// Tree Branch Metadata (64-byte aligned)
// ═══════════════════════════════════════════════════════════════════════════════
struct alignas(64) TreeBranch {
    uint32_t parentIdx;      // Parent node index (0xFFFFFFFF = root)
    uint32_t tokenId;        // Token ID at this node
    uint64_t kvOffset;       // Offset into global KV cache
    float logitScore;        // Cumulative log probability
    uint32_t depth;          // Depth in tree
    uint32_t flags;          // Branch state
    
    // Padding to 64 bytes
    char _padding[40];
    
    enum Flags : uint32_t {
        FLAG_VALID = 1 << 0,
        FLAG_SHARED_PREFIX = 1 << 1,  // Shares KV with parent path
        FLAG_VERIFIED = 1 << 2,         // Passed verification
        FLAG_REJECTED = 1 << 3,           // Failed verification
    };
};

// ═══════════════════════════════════════════════════════════════════════════════
// Tree Causal Mask (DAG structure for attention)
// ═══════════════════════════════════════════════════════════════════════════════
// Unlike linear causal mask (triangular), tree mask allows attention to:
// - All ancestors in the path from root
// - Siblings at the same depth (for comparison)
// - But NOT to other branches' descendants
// ═══════════════════════════════════════════════════════════════════════════════
class TreeCausalMask {
public:
    struct MaskEntry {
        uint32_t nodeIdx;      // Current node
        uint32_t parentIdx;    // Direct parent
        uint32_t depth;        // Depth level
        float attentionWeight; // Optional weight for soft masking
    };
    
private:
    std::vector<MaskEntry> entries_;
    uint32_t nodeCount_ = 0;
    uint32_t maxDepth_ = 0;
    
public:
    void Clear() {
        entries_.clear();
        nodeCount_ = 0;
        maxDepth_ = 0;
    }
    
    // Build mask from tree branches
    void BuildFromBranches(const TreeBranch* branches, uint32_t count) {
        Clear();
        entries_.reserve(count);
        
        for (uint32_t i = 0; i < count; i++) {
            MaskEntry entry{};
            entry.nodeIdx = i;
            entry.parentIdx = branches[i].parentIdx;
            entry.depth = branches[i].depth;
            entry.attentionWeight = 1.0f;
            entries_.push_back(entry);
            
            maxDepth_ = std::max(maxDepth_, entry.depth);
        }
        
        nodeCount_ = count;
    }
    
    // Check if node 'from' can attend to node 'to' in tree structure
    // Returns true if 'to' is an ancestor of 'from' or same depth sibling
    bool CanAttend(uint32_t from, uint32_t to) const {
        if (from >= entries_.size() || to >= entries_.size()) {
            return false;
        }
        
        const auto& fromEntry = entries_[from];
        const auto& toEntry = entries_[to];
        
        // Can always attend to self
        if (from == to) return true;
        
        // Can attend to ancestors (parent chain)
        uint32_t current = from;
        while (current != 0xFFFFFFFF && current < entries_.size()) {
            if (entries_[current].parentIdx == to) {
                return true; // 'to' is ancestor of 'from'
            }
            current = entries_[current].parentIdx;
        }
        
        // Can attend to siblings at same depth (for comparison)
        if (fromEntry.depth == toEntry.depth && 
            fromEntry.parentIdx == toEntry.parentIdx) {
            return true;
        }
        
        return false;
    }
    
    // Get all ancestors of a node (for KV cache loading)
    std::vector<uint32_t> GetAncestors(uint32_t node) const {
        std::vector<uint32_t> ancestors;
        uint32_t current = node;
        
        while (current != 0xFFFFFFFF && current < entries_.size()) {
            ancestors.push_back(current);
            current = entries_[current].parentIdx;
        }
        
        return ancestors;
    }
    
    // Get nodes at specific depth level
    std::vector<uint32_t> GetNodesAtDepth(uint32_t depth) const {
        std::vector<uint32_t> nodes;
        for (uint32_t i = 0; i < entries_.size(); i++) {
            if (entries_[i].depth == depth) {
                nodes.push_back(i);
            }
        }
        return nodes;
    }
    
    uint32_t GetNodeCount() const { return nodeCount_; }
    uint32_t GetMaxDepth() const { return maxDepth_; }
    const std::vector<MaskEntry>& GetEntries() const { return entries_; }
};

// ═══════════════════════════════════════════════════════════════════════════════
// Tree Attention Kernel (extends Flash Attention v2)
// ═══════════════════════════════════════════════════════════════════════════════
class TreeAttentionKernel {
public:
    struct TreeAttentionState {
        // Online softmax state per tree node
        std::vector<float> maxScores;    // Max score per node
        std::vector<float> sumExp;       // Sum of exp scores per node
        std::vector<float> accumO;       // Accumulated output
        
        void Resize(uint32_t nodes) {
            maxScores.resize(nodes, -INFINITY);
            sumExp.resize(nodes, 0.0f);
            accumO.resize(nodes * 128, 0.0f); // Assuming head_dim=128
        }
    };
    
private:
    TreeAttentionConfig config_;
    TreeCausalMask mask_;
    TreeAttentionState state_;
    
    // Block-sparse mask cache for AVX-512
    std::vector<uint8_t> blockMask_;  // 1 = can attend, 0 = masked
    
public:
    explicit TreeAttentionKernel(const TreeAttentionConfig& cfg = {})
        : config_(cfg) {
        blockMask_.resize(cfg.maxNodes * cfg.maxNodes, 0);
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // Core Tree Attention Forward Pass
    // ═══════════════════════════════════════════════════════════════════════════
    // Unlike standard Flash Attention which processes a sequence linearly,
    // Tree Attention processes a DAG where each node may have multiple parents
    // ═══════════════════════════════════════════════════════════════════════════
    void Forward(
        const float* Q,           // Query matrix [num_nodes, head_dim]
        const float* K,           // Key matrix [num_nodes, head_dim]
        const float* V,           // Value matrix [num_nodes, head_dim]
        float* output,            // Output [num_nodes, head_dim]
        const TreeBranch* branches,
        uint32_t numBranches,
        uint32_t headDim = 128
    ) {
        // Build tree mask
        mask_.BuildFromBranches(branches, numBranches);
        state_.Resize(numBranches);
        
        // Generate block-sparse mask for SIMD efficiency
        GenerateBlockMask();
        
        // Process by depth levels (topological order)
        for (uint32_t depth = 0; depth <= mask_.GetMaxDepth(); depth++) {
            auto nodesAtDepth = mask_.GetNodesAtDepth(depth);
            
            // Process all nodes at this depth in parallel
            for (uint32_t nodeIdx : nodesAtDepth) {
                ComputeNodeAttention(
                    Q, K, V, output,
                    nodeIdx, headDim
                );
            }
        }
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // Batch Verification Interface
    // ═══════════════════════════════════════════════════════════════════════════
    // Takes a TreeBatch from the scheduler and verifies all draft tokens
    // in a single kernel launch
    // ═══════════════════════════════════════════════════════════════════════════
    struct VerificationResult {
        uint32_t acceptedCount;           // Number of tokens accepted
        uint32_t firstRejectedIdx;        // Index of first rejection (if any)
        float acceptanceRate;             // % of tokens accepted
        std::vector<uint32_t> acceptedTokens;
    };
    
    VerificationResult VerifyDraftTree(
        const TreeBatch& batch,
        const float* modelLogits,         // Main model output logits
        uint32_t vocabSize
    ) {
        VerificationResult result{};
        
        // Convert TreeBatch to TreeBranch array
        std::vector<TreeBranch> branches;
        branches.reserve(batch.count);
        
        for (uint32_t i = 0; i < batch.count; i++) {
            TreeBranch branch{};
            branch.parentIdx = batch.nodes[i].parent;
            branch.tokenId = batch.nodes[i].token;
            branch.depth = batch.nodes[i].depth;
            branch.logitScore = batch.nodes[i].probability;
            branch.flags = TreeBranch::FLAG_VALID;
            branches.push_back(branch);
        }
        
        // Verify each token (greedy for now, can extend to sampling)
        uint32_t consecutiveAccepted = 0;
        for (uint32_t i = 0; i < batch.count; i++) {
            // Get model's predicted token at this position
            uint32_t modelToken = GreedySample(modelLogits + i * vocabSize, vocabSize);
            
            if (modelToken == branches[i].tokenId) {
                // Token accepted
                branches[i].flags |= TreeBranch::FLAG_VERIFIED;
                result.acceptedTokens.push_back(branches[i].tokenId);
                consecutiveAccepted++;
            } else {
                // Token rejected - stop accepting
                branches[i].flags |= TreeBranch::FLAG_REJECTED;
                result.firstRejectedIdx = i;
                break;
            }
        }
        
        result.acceptedCount = consecutiveAccepted;
        result.acceptanceRate = batch.count > 0 ? 
            (float)consecutiveAccepted / batch.count : 0.0f;
        
        return result;
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // Shared Prefix Optimization
    // ═══════════════════════════════════════════════════════════════════════════
    // Identifies and shares KV cache for common prefixes across branches
    // ═══════════════════════════════════════════════════════════════════════════
    void OptimizeSharedPrefixes(
        TreeBranch* branches,
        uint32_t count,
        const float* kvCache,
        uint64_t kvStride
    ) {
        if (!config_.useSharedPrefix) return;
        
        // Mark nodes that share prefixes with their parents
        for (uint32_t i = 0; i < count; i++) {
            if (branches[i].parentIdx != 0xFFFFFFFF) {
                uint32_t parent = branches[i].parentIdx;
                
                // Check if we can share parent's KV cache
                // (In practice, compare KV vectors for similarity)
                bool canShare = true; // Simplified
                
                if (canShare) {
                    branches[i].kvOffset = branches[parent].kvOffset;
                    branches[i].flags |= TreeBranch::FLAG_SHARED_PREFIX;
                } else {
                    branches[i].kvOffset = i * kvStride;
                }
            }
        }
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // AVX-512 Optimized Mask Generation
    // ═══════════════════════════════════════════════════════════════════════════
    // Generates the tree causal mask using AVX-512 for register-level efficiency
    // ═══════════════════════════════════════════════════════════════════════════
    void GenerateBlockMaskAVX512() {
        // AVX-512 implementation would go here
        // Uses _mm512_mask operations for efficient DAG traversal
        // 
        // Pseudocode for AVX-512:
        //   __m512i nodeIndices = _mm512_set1_epi32(0);
        //   __m512i parentIndices = _mm512_loadu_si512(parents);
        //   __mmask16 validMask = _mm512_cmp_epi32_mask(nodeIndices, parentIndices, _CMP_EQ);
        //   ...
        
        // For now, use scalar fallback
        GenerateBlockMask();
    }
    
    const TreeCausalMask& GetMask() const { return mask_; }
    const TreeAttentionConfig& GetConfig() const { return config_; }
    
private:
    void ComputeNodeAttention(
        const float* Q, const float* K, const float* V,
        float* output, uint32_t nodeIdx, uint32_t headDim
    ) {
        // Get ancestors that this node can attend to
        auto ancestors = mask_.GetAncestors(nodeIdx);
        
        // Compute attention scores (simplified)
        float maxScore = -INFINITY;
        std::vector<float> scores(ancestors.size());
        
        for (size_t i = 0; i < ancestors.size(); i++) {
            uint32_t ancIdx = ancestors[i];
            // Dot product Q[node] · K[anc]
            float score = 0.0f;
            for (uint32_t d = 0; d < headDim; d++) {
                score += Q[nodeIdx * headDim + d] * K[ancIdx * headDim + d];
            }
            score /= sqrtf((float)headDim); // Scale
            scores[i] = score;
            maxScore = std::max(maxScore, score);
        }
        
        // Softmax and weighted sum
        float sumExp = 0.0f;
        for (float score : scores) {
            sumExp += expf(score - maxScore);
        }
        
        // Compute output
        for (uint32_t d = 0; d < headDim; d++) {
            float outVal = 0.0f;
            for (size_t i = 0; i < ancestors.size(); i++) {
                uint32_t ancIdx = ancestors[i];
                float weight = expf(scores[i] - maxScore) / sumExp;
                outVal += weight * V[ancIdx * headDim + d];
            }
            output[nodeIdx * headDim + d] = outVal;
        }
        
        // Update online softmax state
        state_.maxScores[nodeIdx] = maxScore;
        state_.sumExp[nodeIdx] = sumExp;
    }
    
    void GenerateBlockMask() {
        uint32_t n = mask_.GetNodeCount();
        for (uint32_t i = 0; i < n; i++) {
            for (uint32_t j = 0; j < n; j++) {
                blockMask_[i * config_.maxNodes + j] = mask_.CanAttend(i, j) ? 1 : 0;
            }
        }
    }
    
    uint32_t GreedySample(const float* logits, uint32_t vocabSize) {
        uint32_t bestIdx = 0;
        float bestLogit = logits[0];
        for (uint32_t i = 1; i < vocabSize; i++) {
            if (logits[i] > bestLogit) {
                bestLogit = logits[i];
                bestIdx = i;
            }
        }
        return bestIdx;
    }
};

// ═══════════════════════════════════════════════════════════════════════════════
// Integration: Connect Scheduler to Tree Attention
// ═══════════════════════════════════════════════════════════════════════════════
class SpeculativeInferencePipeline {
    SpeculativeScheduler scheduler_;
    TreeAttentionKernel treeKernel_;
    
public:
    struct PipelineResult {
        uint32_t tokensGenerated;
        uint32_t draftTokensAccepted;
        float effectiveTPS;
        float acceptanceRate;
    };
    
    explicit SpeculativeInferencePipeline(
        const SpeculativeScheduler::Config& schedCfg = {},
        const TreeAttentionConfig& treeCfg = {}
    ) : scheduler_(schedCfg), treeKernel_(treeCfg) {}
    
    // Main inference entry point
    PipelineResult RunInference(
        const uint32_t* prompt,
        uint32_t promptLength,
        uint32_t maxNewTokens,
        uint32_t* output,
        uint32_t outputBufferSize
    ) {
        PipelineResult result{};
        uint32_t generated = 0;
        
        // Context for generation
        std::vector<uint32_t> context(prompt, prompt + promptLength);
        
        while (generated < maxNewTokens && generated < outputBufferSize) {
            // Phase 1: Generate drafts
            uint32_t drafts = scheduler_.GenerateDrafts(context.data(), 
                                                        static_cast<uint32_t>(context.size()));
            
            if (drafts == 0) {
                // No drafts - fall back to standard generation
                break;
            }
            
            // Phase 2: Prepare verification batch
            uint32_t batchSize = 0;
            const uint32_t* batch = scheduler_.PrepareVerificationBatch(batchSize);
            
            // Phase 3: Verify through main model (simulated)
            // In production, this calls the actual model forward pass
            std::vector<uint32_t> verified(batchSize);
            for (uint32_t i = 0; i < batchSize; i++) {
                verified[i] = batch[i]; // Simulate perfect acceptance for now
            }
            
            // Phase 4: Process results
            uint32_t accepted = scheduler_.ProcessVerificationResults(verified.data(), batchSize);
            
            // Phase 5: Output accepted tokens
            uint32_t actualAccepted = 0;
            scheduler_.GetAcceptedTokens(output + generated, outputBufferSize - generated, 
                                         actualAccepted);
            
            // Update context and counters
            for (uint32_t i = 0; i < actualAccepted; i++) {
                context.push_back(output[generated + i]);
            }
            generated += actualAccepted;
            result.draftTokensAccepted += actualAccepted;
            
            if (actualAccepted == 0) {
                // All drafts rejected - need fallback
                break;
            }
        }
        
        result.tokensGenerated = generated;
        result.acceptanceRate = scheduler_.GetTelemetry().GetAcceptanceRate();
        result.effectiveTPS = generated * 1000000.0f / 
            (scheduler_.GetTelemetry().draftTimeUs + scheduler_.GetTelemetry().verifyTimeUs);
        
        return result;
    }
    
    const SpeculativeTelemetry& GetTelemetry() const {
        return scheduler_.GetTelemetry();
    }
};

} // namespace RawrXD
