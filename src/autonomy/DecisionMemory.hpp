/**
 * DecisionMemory.hpp
 *
 * Phase C.3 Batch 3/5: Autonomous Learning Memory
 *
 * Connects CheckpointManager, PerformanceBaseline, and EmergentPatternHistory
 * to store decision context, outcomes, and enable learning from experience.
 */

#pragma once

#include "DecisionTypes.hpp"
#include "../runtime/CheckpointManager.hpp"
#include "../telemetry/PerformanceBaseline.hpp"
#include "../emergent/EmergentPatternDetector.hpp"

#include <vector>
#include <map>
#include <memory>
#include <mutex>

namespace Autonomy {

/**
 * Learning entry - stores a single decision experience
 */
struct LearningEntry {
    std::string entryId;
    std::string decisionId;
    
    // Decision details
    DecisionType decisionType;
    DecisionContext contextAtDecision;
    std::vector<Action> actions;
    double predictedUtility;
    double predictedRisk;
    
    // Outcome
    DecisionOutcome outcome;
    double actualReward;
    
    // Temporal info
    int64_t decisionTimestampMs;
    int64_t outcomeTimestampMs;
    int64_t timeToOutcomeMs;
    
    // Pattern context
    std::vector<Emergent::Pattern> patternsAtDecision;
    std::vector<Emergent::Pattern> patternsAfterOutcome;
    
    // Learning metrics
    double predictionError;           // |actual - predicted|
    double confidenceDelta;           // Change in confidence
    bool wasSurprising;               // Outcome differed significantly from prediction
    
    std::string ToJson() const;
    void PrintSummary() const;
};

/**
 * Decision effectiveness model
 */
struct DecisionEffectiveness {
    DecisionType type;
    int totalAttempts{0};
    int successfulAttempts{0};
    double averageReward{0.0};
    double averagePredictionError{0.0};
    double currentConfidence{0.5};    // Learned confidence for this type
    
    void RecordOutcome(const LearningEntry& entry);
    double GetSuccessRate() const;
    std::string ToJson() const;
};

/**
 * Context similarity for finding similar past decisions
 */
struct ContextSimilarity {
    double stabilitySimilarity{0.0};
    double loadSimilarity{0.0};
    double patternSimilarity{0.0};
    
    double Overall() const {
        return (stabilitySimilarity + loadSimilarity + patternSimilarity) / 3.0;
    }
};

/**
 * Memory configuration
 */
struct DecisionMemoryConfig {
    size_t maxEntries{10000};              // Maximum learning entries
    double similarityThreshold{0.7};       // Min similarity for context matching
    double learningRate{0.1};            // How fast to update confidence
    double discountFactor{0.9};            // Future reward discount
    bool enableForgetting{true};           // Remove old low-value entries
    int forgettingAgeMs{86400000};         // Forget entries older than 24h
    
    std::string ToJson() const;
};

/**
 * Decision Memory
 *
 * Stores decision history and enables learning from outcomes.
 * Supports:
 *   - Experience replay
 *   - Context-based retrieval
 *   - Confidence updating
 *   - Pattern-based prediction
 */
class DecisionMemory {
public:
    DecisionMemory();
    ~DecisionMemory();

    // Disable copy, enable move
    DecisionMemory(const DecisionMemory&) = delete;
    DecisionMemory& operator=(const DecisionMemory&) = delete;
    DecisionMemory(DecisionMemory&&) noexcept;
    DecisionMemory& operator=(DecisionMemory&&) noexcept;

    /**
     * Initialize memory system
     */
    bool Initialize(const DecisionMemoryConfig& config);

    /**
     * Shutdown
     */
    void Shutdown();

    /**
     * Record a decision being made
     */
    void RecordDecision(const Decision& decision);

    /**
     * Record the outcome of a decision
     */
    void RecordOutcome(const std::string& decisionId, const DecisionOutcome& outcome);

    /**
     * Find similar past decisions
     */
    std::vector<LearningEntry> FindSimilarDecisions(const DecisionContext& context, 
                                                     int maxResults = 5) const;

    /**
     * Get learning entries for a specific decision type
     */
    std::vector<LearningEntry> GetEntriesForType(DecisionType type, int maxResults = 10) const;

    /**
     * Get effectiveness model for a decision type
     */
    DecisionEffectiveness GetEffectiveness(DecisionType type) const;

    /**
     * Update confidence based on outcomes
     */
    void UpdateConfidence(DecisionType type, double actualReward);

    /**
     * Predict expected utility for a decision type in given context
     */
    double PredictUtility(DecisionType type, const DecisionContext& context) const;

    /**
     * Predict success probability
     */
    double PredictSuccessProbability(DecisionType type, const DecisionContext& context) const;

    /**
     * Get recommended decisions based on learned effectiveness
     */
    std::vector<DecisionType> GetRecommendedDecisions(const DecisionContext& context) const;

    /**
     * Experience replay - sample past experiences for learning
     */
    std::vector<LearningEntry> SampleForReplay(int count) const;

    /**
     * Get statistics
     */
    struct Statistics {
        size_t totalEntries{0};
        size_t entriesWithOutcomes{0};
        double averageReward{0.0};
        double averagePredictionError{0.0};
        std::map<DecisionType, DecisionEffectiveness> effectivenessByType;
        
        void Print() const;
    };
    Statistics GetStatistics() const;

    /**
     * Save memory to disk
     */
    bool Save(const std::string& path) const;

    /**
     * Load memory from disk
     */
    bool Load(const std::string& path);

    /**
     * Clear all memory
     */
    void Clear();

    /**
     * Print status
     */
    void PrintStatus() const;

private:
    DecisionMemoryConfig config_;
    bool initialized_{false};
    
    // Storage
    std::vector<LearningEntry> entries_;
    std::map<std::string, size_t> decisionIdToIndex_;
    std::map<DecisionType, DecisionEffectiveness> effectiveness_;
    
    // Threading
    mutable std::mutex mutex_;
    
    // Helpers
    ContextSimilarity CalculateSimilarity(const DecisionContext& a, 
                                           const DecisionContext& b) const;
    double CalculateReward(const DecisionOutcome& outcome) const;
    void PruneOldEntries();
    void UpdateEffectiveness(const LearningEntry& entry);
    std::string GenerateEntryId() const;
};

/**
 * Performance baseline integration
 */
class PerformanceBaselineIntegration {
public:
    /**
     * Compare current performance to baseline
     */
    static double CalculatePerformanceDelta(const Telemetry::PerformanceBaseline& baseline,
                                           const Telemetry::TelemetrySnapshot& current);
    
    /**
     * Determine if a decision improved performance
     */
    static bool WasDecisionBeneficial(const Decision& decision,
                                     const Telemetry::PerformanceBaseline& before,
                                     const Telemetry::PerformanceBaseline& after);
};

/**
 * Checkpoint integration for state recovery
 */
class CheckpointIntegration {
public:
    /**
     * Create checkpoint before risky decision
     */
    static std::string CreatePreDecisionCheckpoint(Runtime::CheckpointManager& manager,
                                                   const Decision& decision);
    
    /**
     * Determine if rollback is needed
     */
    static bool ShouldRollback(const DecisionOutcome& outcome,
                              const Decision& decision);
    
    /**
     * Execute rollback to checkpoint
     */
    static bool ExecuteRollback(Runtime::CheckpointManager& manager,
                               const std::string& checkpointId);
};

} // namespace Autonomy
