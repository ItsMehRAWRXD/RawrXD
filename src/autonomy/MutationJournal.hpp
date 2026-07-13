/**
 * MutationJournal.hpp
 *
 * Phase C.4 Batch 3/5: Autonomous Rollback Engine
 *
 * Tracks all mutations for reversible execution.
 * Every autonomous change is recorded as a transaction.
 */

#pragma once

#include "../core/SovereignState.hpp"
#include "../seg/SEGMutationEngine.hpp"
#include "DecisionTypes.hpp"

#include <cstring>
#include <vector>
#include <map>
#include <memory>
#include <optional>

namespace Autonomy {

/**
 * Mutation type enumeration
 */
enum class MutationType {
    UNKNOWN,
    ADD_PARALLEL_PATH,
    REMOVE_PARALLEL_PATH,
    MERGE_NODES,
    SPLIT_NODES,
    ADJUST_WEIGHTS,
    CHANGE_PRIORITY,
    INSERT_ISOLATION,
    REMOVE_ISOLATION,
    REMOVE_REDUNDANCY,
    RESTORE_REDUNDANCY,
    MODIFY_ROLE,
    ADJUST_INTENT_STRENGTH,
    SCHEDULER_RECONFIG
};

std::string MutationTypeToString(MutationType type);
MutationType StringToMutationType(const std::string& str);

/**
 * System snapshot
 */
struct SystemSnapshot {
    uint64_t snapshotId{0};
    uint64_t timestampMs{0};
    
    // SEG state
    int nodeCount{0};
    int edgeCount{0};
    std::map<std::string, std::string> nodeStates;
    std::map<std::string, double> edgeWeights;
    
    // Scheduler state
    std::map<std::string, std::string> schedulerConfig;
    std::vector<std::string> activeTasks;
    
    // Agent roles
    std::map<std::string, std::string> agentRoles;
    
    // Decision memory
    std::vector<std::string> recentDecisions;
    
    // Resource state
    double cpuUsage{0.0};
    double memoryUsage{0.0};
    
    // Stability metrics
    double convergenceScore{0.0};
    double stabilityScore{0.0};
    
    std::string ToJson() const;
    void Print() const;
};

/**
 * Performance delta
 */
struct PerformanceDelta {
    double convergenceBefore{0.0};
    double convergenceAfter{0.0};
    double latencyBeforeMs{0.0};
    double latencyAfterMs{0.0};
    double throughputBefore{0.0};
    double throughputAfter{0.0};
    double resourceUsageBefore{0.0};
    double resourceUsageAfter{0.0};
    
    bool IsImprovement() const;
    std::string ToJson() const;
};

/**
 * Decision context
 */
struct DecisionContext {
    std::string decisionId;
    std::string decisionType;
    double confidence{0.0};
    std::map<std::string, std::string> parameters;
    std::string reasoning;
    
    std::string ToJson() const;
};

/**
 * Mutation record
 */
struct MutationRecord {
    uint64_t mutationId{0};
    std::optional<uint64_t> parentMutation;
    MutationType type{MutationType::UNKNOWN};
    
    SystemSnapshot before;
    SystemSnapshot after;
    DecisionContext decision;
    PerformanceDelta delta;
    
    uint64_t timestampMs{0};
    bool committed{false};
    bool rolledBack{false};
    std::optional<uint64_t> rollbackMutationId;
    
    // Reversal data
    std::map<std::string, std::string> reversalData;
    
    std::string ToJson() const;
    void Print() const;
    
    // Check if mutation improved performance
    bool WasSuccessful() const;
    
    // Get reversal mutation type
    MutationType GetReversalType() const;
};

/**
 * Rollback policy
 */
enum class RollbackPolicy {
    ON_FAILURE,           // Rollback on explicit failure
    ON_OSCILLATION,       // Rollback when oscillation detected
    ON_CONVERGENCE_DROP,  // Rollback when convergence drops
    ON_MEMORY_PRESSURE,   // Rollback under memory pressure
    ON_TIMEOUT,          // Rollback on execution timeout
    MANUAL,              // Only manual rollback
    AUTONOMOUS           // System decides when to rollback
};

std::string RollbackPolicyToString(RollbackPolicy policy);

/**
 * Mutation journal configuration
 */
struct MutationJournalConfig {
    size_t maxJournalSize{1000};           // Max records to keep
    size_t maxSnapshotHistory{100};        // Max snapshots
    bool enableCompression{true};          // Compress snapshots
    bool enableBranching{true};            // Allow branching histories
    RollbackPolicy defaultPolicy{RollbackPolicy::AUTONOMOUS};
    int autoRollbackThresholdMs{5000};     // Auto rollback timeout
    double convergenceDropThreshold{0.2};  // Rollback if convergence drops by 20%
    
    std::string ToJson() const;
};

/**
 * Mutation Journal
 *
 * Records all mutations for reversible execution.
 */
class MutationJournal {
public:
    MutationJournal();
    ~MutationJournal();

    // Disable copy
    MutationJournal(const MutationJournal&) = delete;
    MutationJournal& operator=(const MutationJournal&) = delete;

    /**
     * Initialize journal
     */
    bool Initialize(const MutationJournalConfig& config);

    /**
     * Begin mutation recording
     */
    uint64_t BeginMutation(MutationType type, 
                          const SystemSnapshot& before,
                          const DecisionContext& decision);

    /**
     * Complete mutation recording
     */
    bool CompleteMutation(uint64_t mutationId, 
                         const SystemSnapshot& after,
                         const PerformanceDelta& delta);

    /**
     * Commit mutation (mark as permanent)
     */
    bool CommitMutation(uint64_t mutationId);

    /**
     * Get mutation record
     */
    std::optional<MutationRecord> GetMutation(uint64_t mutationId) const;

    /**
     * Get recent mutations
     */
    std::vector<MutationRecord> GetRecentMutations(int count = 10) const;

    /**
     * Get mutation chain (parent -> child)
     */
    std::vector<MutationRecord> GetMutationChain(uint64_t mutationId) const;

    /**
     * Find mutations since snapshot
     */
    std::vector<MutationRecord> GetMutationsSince(uint64_t snapshotId) const;

    /**
     * Mark mutation as rolled back
     */
    bool MarkRolledBack(uint64_t mutationId, uint64_t rollbackMutationId);

    /**
     * Get last committed mutation
     */
    std::optional<MutationRecord> GetLastCommittedMutation() const;

    /**
     * Get last stable mutation (successful + committed)
     */
    std::optional<MutationRecord> GetLastStableMutation() const;

    /**
     * Prune old mutations
     */
    void PruneOldMutations(size_t keepCount);

    /**
     * Clear journal
     */
    void Clear();

    /**
     * Get journal statistics
     */
    struct JournalStats {
        size_t totalMutations{0};
        size_t committedMutations{0};
        size_t rolledBackMutations{0};
        size_t pendingMutations{0};
        size_t successfulMutations{0};
        double successRate{0.0};
    };
    JournalStats GetStats() const;

    /**
     * Print status
     */
    void PrintStatus() const;

    /**
     * Export journal to JSON
     */
    std::string ExportToJson() const;

    /**
     * Replay mutations from snapshot
     */
    bool ReplayFromSnapshot(uint64_t snapshotId, 
                           std::vector<MutationRecord>& replayed) const;

private:
    MutationJournalConfig config_;
    bool initialized_{false};
    
    // Mutation storage
    std::map<uint64_t, MutationRecord> mutations_;
    mutable std::mutex mutationsMutex_;
    
    // Mutation counter
    std::atomic<uint64_t> mutationCounter_{0};
    
    // Snapshot storage
    std::map<uint64_t, SystemSnapshot> snapshots_;
    mutable std::mutex snapshotsMutex_;
    
    // Snapshot counter
    std::atomic<uint64_t> snapshotCounter_{0};
    
    // Helpers
    uint64_t GenerateMutationId();
    uint64_t GenerateSnapshotId();
    int64_t GetCurrentTimeMs() const;
    void PruneIfNeeded();
};

/**
 * CLI for testing mutation journal
 */
class MutationJournalCLI {
public:
    static void PrintBanner();
    static void PrintUsage();
    static int Run(int argc, char* argv[]);
    
private:
    static void InteractiveMode(MutationJournal& journal);
    static void SimulateMutation(MutationJournal& journal, MutationType type);
};

} // namespace Autonomy
