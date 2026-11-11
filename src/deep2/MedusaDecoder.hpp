// ============================================================================
// MedusaDecoder.hpp - Speculative Multi-Head Decoding
//
// VAL-000 Component: Execution → Medusa Heads + Speculative Decode
//
// Medusa adds multiple prediction heads to the LM head, each predicting
// tokens at different positions ahead. The main model verifies these
// speculative tokens in a single forward pass, accepting the longest
// verified prefix. This provides 2-3x throughput improvement with no
// quality loss.
//
// Architecture:
//   Main model hidden state
//       ↓
//   LM Head (token t+1) ← always correct
//       ↓
//   Medusa Head 1 (token t+2) ← speculative
//   Medusa Head 2 (token t+3) ← speculative
//   Medusa Head 3 (token t+4) ← speculative
//   Medusa Head 4 (token t+5) ← speculative
//       ↓
//   Tree verification: accept longest matching prefix
//
// Copyright (c) 2026 RawrXD Sovereign Runtime - VAL-000 Phase 3
// ============================================================================

#ifndef DEEP2_MEDUSA_DECODER_HPP
#define DEEP2_MEDUSA_DECODER_HPP

#include <cstddef>
#include <cstdint>
#include <vector>
#include <memory>
#include <cmath>
#include <algorithm>
#include <cstdio>

namespace Deep2 {

// ---------------------------------------------------------------------------
// Medusa configuration
// ---------------------------------------------------------------------------
struct MedusaConfig {
    size_t numHeads = 4;           // Number of speculative heads
    size_t topKPerHead = 10;       // Candidates per head (tree width)
    size_t maxTreeSize = 40;       // Max total candidates in tree
    float  temperature = 0.0f;     // 0 = greedy, >0 = sampling
    bool   enabled = true;
    size_t minAcceptLength = 2;    // Minimum accepted to keep using Medusa
    size_t maxConsecutiveFails = 5; // Disable after N consecutive failures
};

// ---------------------------------------------------------------------------
// Medusa head weights (lightweight linear projections)
// Each head: [vocabSize, hiddenDim] - predicts token at position +headIdx+2
// ---------------------------------------------------------------------------
struct MedusaHeadWeights {
    const void* weightData = nullptr;  // [vocabSize, hiddenDim]
    int         quantType  = 0;        // GGMLType
    size_t      rows       = 0;        // vocabSize
    size_t      cols       = 0;        // hiddenDim
    size_t      sizeBytes  = 0;
};

// ---------------------------------------------------------------------------
// Speculative candidate from a Medusa head
// ---------------------------------------------------------------------------
struct MedusaCandidate {
    int   tokenId;
    float probability;
    int   headIndex;     // Which head predicted this
    int   parentIndex;   // Index in candidate tree (-1 = root)
};

// ---------------------------------------------------------------------------
// Speculative tree node
// ---------------------------------------------------------------------------
struct SpeculativeTreeNode {
    int   tokenId;
    float probability;
    int   parentId;       // -1 for root
    int   depth;          // 1 = direct child of accepted token
    bool  accepted;      // Set during verification
};

// ---------------------------------------------------------------------------
// Medusa statistics
// ---------------------------------------------------------------------------
struct MedusaStats {
    uint64_t totalSpeculations = 0;
    uint64_t totalAccepted = 0;
    uint64_t totalRejected = 0;
    uint64_t consecutiveFails = 0;
    double   acceptanceRate = 0.0;
    double   avgAcceptedPerStep = 0.0;
    double   speedupEstimate = 1.0;
    bool     autoDisabled = false;

    void update(bool anyAccepted, size_t numAccepted) {
        totalSpeculations++;
        if (anyAccepted) {
            totalAccepted += numAccepted;
            consecutiveFails = 0;
        } else {
            totalRejected++;
            consecutiveFails++;
        }
        if (totalSpeculations > 0) {
            acceptanceRate = (double)totalAccepted / (totalSpeculations + totalAccepted);
            avgAcceptedPerStep = (double)totalAccepted / totalSpeculations;
            speedupEstimate = 1.0 + avgAcceptedPerStep;
        }
    }
};

// ---------------------------------------------------------------------------
// MedusaDecoder - Speculative multi-head decoding engine
// ---------------------------------------------------------------------------
class MedusaDecoder {
public:
    MedusaDecoder();
    ~MedusaDecoder();

    // Initialize with config and head weights
    bool initialize(const MedusaConfig& config);

    // Register a Medusa head's weights
    void setHeadWeights(size_t headIndex, const MedusaHeadWeights& weights);

    // Generate speculative candidates from hidden state
    // Returns a tree of candidate tokens for verification
    std::vector<SpeculativeTreeNode> generateCandidates(
        const float* hiddenState,
        size_t hiddenDim,
        const int* lastAcceptedToken,  // For tree construction
        size_t numLastTokens
    );

    // Verify candidates against main model's logits
    // Returns number of accepted tokens, fills acceptedTokens
    size_t verifyCandidates(
        const std::vector<SpeculativeTreeNode>& candidates,
        const float* mainLogits,         // [vocabSize] for current position
        size_t vocabSize,
        int* acceptedTokens,             // Output: accepted token IDs
        size_t maxAccept
    );

    // Check if Medusa should be used (auto-disable on poor performance)
    bool shouldSpeculate() const;

    // Get statistics
    const MedusaStats& getStats() const { return stats_; }

    // Reset statistics
    void resetStats() { stats_ = MedusaStats{}; }

    // Update config at runtime
    void setConfig(const MedusaConfig& config) { config_ = config; }
    const MedusaConfig& getConfig() const { return config_; }

    // Check if head weights are loaded for a given head
    bool hasHeadWeights(size_t headIndex) const {
        return headIndex < numHeads_ && heads_[headIndex].weightData != nullptr;
    }

    // Project hidden state through a Medusa head to get logits
    void projectHead(size_t headIndex, const float* hiddenState, float* logits, size_t vocabSize);

private:
    MedusaConfig config_;
    MedusaHeadWeights heads_[16];  // Max 16 heads
    size_t numHeads_ = 0;
    MedusaStats stats_;

    // Generate top-k candidates from a single head's logits
    void topKFromLogits(const float* logits, size_t vocabSize,
                        size_t k, std::vector<MedusaCandidate>& out,
                        int headIndex, int parentIndex);

    // Build tree from per-head candidates
    std::vector<SpeculativeTreeNode> buildTree(
        const std::vector<std::vector<MedusaCandidate>>& perHeadCandidates,
        const int* lastAcceptedToken,
        size_t numLastTokens
    );
};

} // namespace Deep2

#endif // DEEP2_MEDUSA_DECODER_HPP
