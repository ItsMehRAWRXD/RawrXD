#pragma once

#include "RawrXD_TreeAttention.hpp"
#include "../fabric/FabricJukeboxBridge.h"
#include <cstdint>
#include <array>
#include <atomic>
#include <memory>
#include <functional>

namespace RawrXD {
namespace Inference {

// ============================================================================
// VAL-032: Draft Token Manager
// 
// Manages draft token generation and verification using a lock-free
// ring buffer (adapted from FabricTransport design).
// 
// Flow:
// 1. Draft model generates candidate tokens (fast, small model)
// 2. DraftManager queues them in tree structure
// 3. TreeAttention kernel verifies all candidates in parallel
// 4. Accepted tokens appended to verified sequence
// 5. Rejected tokens discarded, process repeats
// ============================================================================

// Draft token entry in ring buffer
struct alignas(64) DraftTokenEntry {
    uint32_t tokenId;           // Token ID from draft model
    uint32_t position;          // Position in sequence
    float probability;          // Draft model probability
    float cumulativeScore;      // Running product of probs
    uint32_t parentIdx;         // Parent in tree (for tree structure)
    uint32_t depth;             // Depth in tree
    std::atomic<uint32_t> state; // 0=empty, 1=writing, 2=ready, 3=consumed
    uint32_t pad[2];            // Padding to 64 bytes
    
    DraftTokenEntry() 
        : tokenId(0), position(0), probability(0.0f), 
          cumulativeScore(0.0f), parentIdx(0), depth(0), state(0) {
        pad[0] = pad[1] = 0;
    }
};

// Ring buffer configuration
struct DraftBufferConfig {
    static constexpr uint32_t SIZE = 256;           // Must be power of 2
    static constexpr uint32_t MASK = SIZE - 1;
    static constexpr uint32_t HIGH_WATER_MARK = 192; // 75% full
    static constexpr uint32_t LOW_WATER_MARK = 64;  // 25% full
};

// Draft generation strategy
enum class DraftStrategy : uint32_t {
    STATIC_TREE = 1,      // Fixed 4x4 tree structure
    ADAPTIVE_TREE = 2,    // Dynamic branching based on confidence
    SEQUENTIAL = 3         // No speculation (baseline)
};

// Verification result
struct VerificationResult {
    uint32_t acceptedCount;                    // Number of tokens accepted
    std::array<uint32_t, 85> acceptedTokens; // Accepted token IDs
    std::array<uint32_t, 85> acceptedPositions; // Positions in sequence
    float acceptanceRate;                    // accepted / total
    uint64_t verificationTimeUs;             // Time to verify
};

// ============================================================================
// Draft Manager
// ============================================================================

class DraftManager {
public:
    DraftManager();
    ~DraftManager();
    
    // Initialization
    bool Initialize(DraftStrategy strategy = DraftStrategy::STATIC_TREE,
                   uint32_t draftModelId = 0);  // 0 = use main model for draft
    void Shutdown();
    
    // Draft generation
    // Called by draft model to produce candidate tokens
    bool SubmitDraftToken(uint32_t tokenId, float probability, 
                         uint32_t parentIdx, uint32_t depth);
    
    // Batch submit for tree construction
    bool SubmitDraftTree(const std::array<TreeNode, TreeConfig::MAX_NODES>& nodes,
                        uint32_t nodeCount);
    
    // Verification
    // Called by main model to verify draft tokens
    bool PrepareVerificationBatch(std::array<TreeNode, TreeConfig::MAX_NODES>& nodes,
                                 uint32_t& nodeCount);
    
    // Process verification results
    bool ProcessVerificationResults(const VerificationResult& results);
    
    // Get next verified token
    // Returns: true if token available, false if buffer empty
    bool GetVerifiedToken(uint32_t& tokenId, uint32_t& position);
    
    // Statistics
    struct Stats {
        uint64_t draftTokensGenerated;
        uint64_t draftTokensAccepted;
        uint64_t draftTokensRejected;
        uint64_t verificationBatches;
        double avgAcceptanceRate;
        double avgDraftLatencyUs;
        double avgVerifyLatencyUs;
        uint32_t currentBufferDepth;
    };
    Stats GetStats() const;
    
    // Configuration
    void SetAcceptanceThreshold(float threshold);  // Min probability to accept
    void SetMaxTreeDepth(uint32_t depth);          // Limit tree depth
    void EnableAdaptiveBranching(bool enable);   // Dynamic vs static
    
    // Integration with Fabric
    // When using distributed draft models
    bool SetFabricProvider(Fabric::FabricBlockProvider* provider);
    
private:
    DraftStrategy strategy_;
    uint32_t draftModelId_;
    bool initialized_;
    bool shutdown_;
    
    // Lock-free ring buffer (adapted from FabricTransport)
    alignas(64) std::atomic<uint32_t> writeIdx_{0};
    alignas(64) std::atomic<uint32_t> readIdx_{0};
    alignas(64) DraftTokenEntry ringBuffer_[DraftBufferConfig::SIZE];
    
    // Current tree being built
    std::array<TreeNode, TreeConfig::MAX_NODES> currentTree_;
    uint32_t currentTreeSize_;
    
    // Verified token queue (separate from draft buffer)
    alignas(64) std::atomic<uint32_t> verifiedWriteIdx_{0};
    alignas(64) std::atomic<uint32_t> verifiedReadIdx_{0};
    struct VerifiedToken {
        uint32_t tokenId;
        uint32_t position;
    };
    VerifiedToken verifiedQueue_[DraftBufferConfig::SIZE];
    
    // Configuration
    float acceptanceThreshold_;
    uint32_t maxTreeDepth_;
    bool adaptiveBranching_;
    
    // Fabric integration
    Fabric::FabricBlockProvider* fabricProvider_;
    
    // Statistics
    alignas(64) std::atomic<uint64_t> draftGenerated_{0};
    alignas(64) std::atomic<uint64_t> draftAccepted_{0};
    alignas(64) std::atomic<uint64_t> draftRejected_{0};
    alignas(64) std::atomic<uint64_t> verifyBatches_{0};
    alignas(64) std::atomic<uint64_t> totalDraftLatencyUs_{0};
    alignas(64) std::atomic<uint64_t> totalVerifyLatencyUs_{0};
    
    // Helper methods
    bool IsBufferFull() const;
    bool IsBufferEmpty() const;
    uint32_t GetBufferDepth() const;
    
    uint64_t GetTimestampUs() const;
    
    // Tree building
    bool BuildStaticTree();
    bool BuildAdaptiveTree();
    
    // Verification
    bool VerifyAgainstTarget(const TreeAttentionParams& params,
                            VerificationResult& result);
};

// ============================================================================
// Speculative Decoding Pipeline
// 
// High-level orchestration of draft -> verify -> accept flow
// ============================================================================

class SpeculativeDecoder {
public:
    SpeculativeDecoder();
    ~SpeculativeDecoder();
    
    // Initialize with draft and target models
    bool Initialize(uint32_t draftModelId, uint32_t targetModelId,
                   DraftManager* draftManager,
                   TreeAttentionKernel* attentionKernel);
    void Shutdown();
    
    // Generate next token with speculation
    // Returns: token ID and number of bonus tokens from speculation
    struct DecodeResult {
        uint32_t tokenId;
        uint32_t bonusTokens;      // Extra tokens from accepted drafts
        uint64_t latencyUs;
        float acceptanceRate;
    };
    DecodeResult GenerateNextToken(const uint32_t* promptTokens, 
                                  uint32_t promptLen);
    
    // Batch decode for higher throughput
    std::vector<DecodeResult> GenerateBatch(
        const std::vector<std::vector<uint32_t>>& prompts);
    
    // Performance tuning
    void SetSpeculationDepth(uint32_t depth);     // How many tokens to draft
    void SetVerificationThreshold(float threshold); // Acceptance threshold
    
    // Statistics
    struct Stats {
        uint64_t totalTokensGenerated;
        uint64_t totalDraftTokens;
        uint64_t totalAcceptedTokens;
        double avgTokensPerStep;
        double speedupVsGreedy;  // Measured speedup
    };
    Stats GetStats() const;
    
private:
    uint32_t draftModelId_;
    uint32_t targetModelId_;
    DraftManager* draftManager_;
    TreeAttentionKernel* attentionKernel_;
    bool initialized_;
    
    uint32_t speculationDepth_;
    float verificationThreshold_;
    
    // Statistics
    alignas(64) std::atomic<uint64_t> totalTokens_{0};
    alignas(64) std::atomic<uint64_t> totalDraft_{0};
    alignas(64) std::atomic<uint64_t> totalAccepted_{0};
    alignas(64) std::atomic<uint64_t> totalSteps_{0};
};

// ============================================================================
// Performance Targets
// ============================================================================

// Target: 2,000+ TPS with speculative decoding
// Baseline (greedy): ~1,125 TPS
// With 4x4 tree speculation: ~2,250 TPS (2x speedup)
// Acceptance rate target: >70%

struct SpeculativeDecodingTargets {
    static constexpr double TARGET_TPS = 2000.0;
    static constexpr double BASELINE_TPS = 1125.0;
    static constexpr double TARGET_SPEEDUP = 1.8;  // 1.8x vs greedy
    static constexpr double TARGET_ACCEPTANCE_RATE = 0.70;
    static constexpr uint32_t TARGET_LATENCY_MS = 10;  // Per step
};

} // namespace Inference
} // namespace RawrXD
