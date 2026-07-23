// ============================================================================
// IntentCompression.hpp - Compact Machine State Protocol
// Replaces giant chat histories with: goal, current state, blockers, next action
// ============================================================================

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <unordered_map>

namespace Sovereign {

// Compact state
struct CompactState {
    std::string goal;
    std::string currentState;
    std::vector<std::string> blockers;
    std::string nextAction;
    uint64_t timestamp;
    uint64_t iteration;
    float progress; // 0.0 - 1.0
    std::vector<std::string> recentResults;
    std::vector<std::string> recentErrors;
};

// State delta (changes only)
struct StateDelta {
    std::string field;
    std::string oldValue;
    std::string newValue;
    uint64_t timestamp;
};

// Intent compression protocol
class IntentCompression {
public:
    IntentCompression();
    ~IntentCompression();

    // Compression
    CompactState Compress(const std::vector<std::string>& history, const std::string& goal);
    CompactState CompressWithState(const std::string& goal, const std::string& state,
                                    const std::vector<std::string>& blockers);
    std::string Decompress(const CompactState& state);

    // Delta encoding
    StateDelta ComputeDelta(const CompactState& before, const CompactState& after);
    CompactState ApplyDelta(const CompactState& state, const StateDelta& delta);
    std::vector<StateDelta> ComputeDeltas(const std::vector<CompactState>& states);

    // Token optimization
    size_t EstimateTokens(const CompactState& state) const;
    size_t EstimateTokens(const std::vector<std::string>& history) const;
    double CompressionRatio(const std::vector<std::string>& history, const CompactState& state) const;

    // State machine
    void SetStateMachine(std::function<CompactState(const std::string&)> machine);
    CompactState Execute(const std::string& goal);

    // Serialization
    std::string Serialize(const CompactState& state);
    CompactState Deserialize(const std::string& data);

    // Statistics
    struct CompressionStats {
        uint64_t totalCompressions;
        uint64_t totalDecompressions;
        uint64_t totalTokensSaved;
        double avgCompressionRatio;
    };
    CompressionStats GetStats() const { return stats_; }
    void ResetStats();

private:
    CompressionStats stats_;
    std::function<CompactState(const std::string&)> stateMachine_;
    
    std::string ExtractGoal(const std::vector<std::string>& history) const;
    std::vector<std::string> ExtractBlockers(const std::vector<std::string>& history) const;
    std::string ExtractNextAction(const std::vector<std::string>& history) const;
    float EstimateProgress(const std::vector<std::string>& history) const;
};

} // namespace Sovereign
