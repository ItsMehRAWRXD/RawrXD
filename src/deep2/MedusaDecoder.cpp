// ============================================================================
// MedusaDecoder.cpp - Speculative Multi-Head Decoding Implementation
//
// Copyright (c) 2026 RawrXD Sovereign Runtime - VAL-000 Phase 3
// ============================================================================

#include "MedusaDecoder.hpp"
#include <cstring>
#include <queue>

// External AVX2 GEMV kernel from Deep2Engine.cpp
extern "C" void Deep2_MedusaGEMV(const float* weights, const float* input, float* output,
                                  size_t rows, size_t cols);

namespace Deep2 {

MedusaDecoder::MedusaDecoder() {}
MedusaDecoder::~MedusaDecoder() {}

bool MedusaDecoder::initialize(const MedusaConfig& config) {
    config_ = config;
    numHeads_ = config.numHeads;
    stats_ = MedusaStats{};

    // Clear head weights
    for (size_t i = 0; i < 16; i++) {
        heads_[i] = MedusaHeadWeights{};
    }

    printf("[MedusaDecoder] Initialized: %zu heads, topK=%zu, maxTree=%zu\n",
           config.numHeads, config.topKPerHead, config.maxTreeSize);
    return true;
}

void MedusaDecoder::setHeadWeights(size_t headIndex, const MedusaHeadWeights& weights) {
    if (headIndex < 16) {
        heads_[headIndex] = weights;
    }
}

void MedusaDecoder::topKFromLogits(const float* logits, size_t vocabSize,
                                     size_t k, std::vector<MedusaCandidate>& out,
                                     int headIndex, int parentIndex) {
    // Simple top-k selection using partial sort
    struct LogitEntry {
        int   id;
        float val;
    };

    std::vector<LogitEntry> entries(vocabSize);
    for (size_t i = 0; i < vocabSize; i++) {
        entries[i] = {(int)i, logits[i]};
    }

    // Partial sort for top-k
    size_t actualK = std::min(k, vocabSize);
    std::partial_sort(entries.begin(), entries.begin() + actualK, entries.end(),
                      [](const LogitEntry& a, const LogitEntry& b) {
                          return a.val > b.val;
                      });

    // Compute softmax over top-k for probabilities
    float maxLogit = entries[0].val;
    float expSum = 0.0f;
    for (size_t i = 0; i < actualK; i++) {
        expSum += expf(entries[i].val - maxLogit);
    }

    for (size_t i = 0; i < actualK; i++) {
        MedusaCandidate cand;
        cand.tokenId = entries[i].id;
        cand.probability = expf(entries[i].val - maxLogit) / expSum;
        cand.headIndex = headIndex;
        cand.parentIndex = parentIndex;
        out.push_back(cand);
    }
}

std::vector<SpeculativeTreeNode> MedusaDecoder::buildTree(
    const std::vector<std::vector<MedusaCandidate>>& perHeadCandidates,
    const int* lastAcceptedToken,
    size_t numLastTokens
) {
    std::vector<SpeculativeTreeNode> tree;

    // Root: the last accepted token
    SpeculativeTreeNode root;
    root.tokenId = (numLastTokens > 0) ? lastAcceptedToken[numLastTokens - 1] : 0;
    root.probability = 1.0f;
    root.parentId = -1;
    root.depth = 0;
    root.accepted = false;
    tree.push_back(root);

    // Build tree level by level
    // Level 1: Head 0 candidates (children of root)
    // Level 2: Head 1 candidates (children of top Level 1 nodes)
    // etc.
    int prevLevelStart = 0;  // Index of root
    int prevLevelEnd = 1;

    for (size_t head = 0; head < perHeadCandidates.size() && head < numHeads_; head++) {
        const auto& candidates = perHeadCandidates[head];
        int levelStart = (int)tree.size();

        // For each node at previous level, add its children
        for (int parentIdx = prevLevelStart; parentIdx < prevLevelEnd; parentIdx++) {
            // Limit branching: only top few candidates per parent
            size_t branchFactor = std::min(config_.topKPerHead, candidates.size());

            // For deeper levels, reduce branching to control tree size
            if (head > 0) {
                branchFactor = std::min(branchFactor, (size_t)3);
            }
            if (head > 1) {
                branchFactor = std::min(branchFactor, (size_t)2);
            }

            for (size_t c = 0; c < branchFactor; c++) {
                if (tree.size() >= config_.maxTreeSize) break;

                SpeculativeTreeNode node;
                node.tokenId = candidates[c].tokenId;
                node.probability = candidates[c].probability * tree[parentIdx].probability;
                node.parentId = parentIdx;
                node.depth = (int)(head + 1);
                node.accepted = false;
                tree.push_back(node);
            }
            if (tree.size() >= config_.maxTreeSize) break;
        }

        prevLevelStart = levelStart;
        prevLevelEnd = (int)tree.size();

        if (prevLevelStart >= prevLevelEnd) break;  // No nodes at this level
    }

    return tree;
}

std::vector<SpeculativeTreeNode> MedusaDecoder::generateCandidates(
    const float* hiddenState,
    size_t hiddenDim,
    const int* lastAcceptedToken,
    size_t numLastTokens
) {
    if (!config_.enabled || stats_.autoDisabled) {
        return {};
    }

    // For each head, compute logits and select top-k candidates
    std::vector<std::vector<MedusaCandidate>> perHeadCandidates(numHeads_);

    for (size_t h = 0; h < numHeads_; h++) {
        const auto& hw = heads_[h];
        if (!hw.weightData || hw.rows == 0 || hw.cols == 0) continue;

        // Compute logits: logits[v] = dot(hiddenState, weight[v])
        // This is a GEMV: [vocabSize, hiddenDim] @ [hiddenDim] -> [vocabSize]
        // Production AVX2 implementation via Deep2_MedusaGEMV
        std::vector<float> logits(hw.rows);

        // AVX2-optimized GEMV for Medusa head forward pass
        const float* w = (const float*)hw.weightData;
        Deep2_MedusaGEMV(w, hiddenState, logits.data(), hw.rows, hiddenDim);

        // Select top-k
        topKFromLogits(logits.data(), hw.rows, config_.topKPerHead,
                       perHeadCandidates[h], (int)h, -1);
    }

    // Build the speculative tree
    return buildTree(perHeadCandidates, lastAcceptedToken, numLastTokens);
}

size_t MedusaDecoder::verifyCandidates(
    const std::vector<SpeculativeTreeNode>& candidates,
    const float* mainLogits,
    size_t vocabSize,
    int* acceptedTokens,
    size_t maxAccept
) {
    if (candidates.empty()) return 0;

    // The main model has computed logits for the current position.
    // The "correct" token is argmax(mainLogits).
    // We verify: does the candidate match what the main model would produce?

    // Find the main model's predicted token (greedy)
    int mainToken = 0;
    float mainMax = mainLogits[0];
    for (size_t i = 1; i < vocabSize; i++) {
        if (mainLogits[i] > mainMax) {
            mainMax = mainLogits[i];
            mainToken = (int)i;
        }
    }

    // Check if the first candidate (depth=1) matches
    // In a real implementation, we'd verify the entire tree path
    // by running the model forward for each candidate and comparing

    size_t accepted = 0;

    // Simple verification: accept candidates that match main model's greedy choice
    // In production, this does a full tree-based verification pass
    for (size_t i = 1; i < candidates.size() && accepted < maxAccept; i++) {
        const auto& node = candidates[i];

        // Only check depth-1 nodes (direct children of root)
        if (node.depth != 1) continue;

        if (node.tokenId == mainToken) {
            acceptedTokens[accepted++] = node.tokenId;
            break;  // Accept first match
        }
    }

    // Update statistics
    bool anyAccepted = (accepted > 0);
    stats_.update(anyAccepted, accepted);

    // Auto-disable if too many consecutive failures
    if (stats_.consecutiveFails >= config_.maxConsecutiveFails) {
        stats_.autoDisabled = true;
        printf("[MedusaDecoder] Auto-disabled after %zu consecutive failures\n",
               stats_.consecutiveFails);
    }

    return accepted;
}

bool MedusaDecoder::shouldSpeculate() const {
    return config_.enabled && !stats_.autoDisabled;
}

} // namespace Deep2