/**
 * SEGMutationEngine.hpp
 *
 * Phase C.3 Batch 2/5: SEG Autonomous Mutation
 *
 * Allows autonomous decisions to dynamically modify the execution graph.
 * Supports edge weighting, node priority, parallel execution, and failure isolation.
 */

#pragma once

#include "../seg/ExecutionGraph.hpp"
#include "DecisionTypes.hpp"
#include <vector>
#include <memory>
#include <functional>

namespace Autonomy {

// Forward declarations
class AutonomousDecisionEngine;

/**
 * Types of mutations that can be applied to the execution graph
 */
enum class MutationType {
    REORDER_EDGES,          // Change execution order
    ADD_PARALLEL_PATH,      // Create parallel execution branch
    MERGE_NODES,            // Combine multiple nodes
    SPLIT_NODE,             // Break node into sub-tasks
    ADJUST_WEIGHTS,         // Modify edge weights
    CHANGE_PRIORITY,        // Modify node priorities
    INSERT_ISOLATION,       // Add failure isolation boundary
    REMOVE_REDUNDANCY,      // Eliminate duplicate work
    OPTIMIZE_CRITICAL_PATH, // Focus on critical path
    NONE
};

/**
 * Represents a mutation to be applied to the execution graph
 */
struct SEGMutation {
    std::string mutationId;
    MutationType type{MutationType::NONE};
    std::string description;
    
    // Target nodes/edges
    std::vector<std::string> targetNodes;
    std::vector<std::pair<std::string, std::string>> targetEdges;
    
    // Mutation parameters
    std::map<std::string, std::string> parameters;
    
    // Expected impact
    double expectedSpeedup{0.0};        // Expected performance improvement
    double riskScore{0.0};              // Risk of mutation
    bool isReversible{true};            // Can be rolled back
    
    // Methods
    std::string ToJson() const;
    std::string ToNaturalLanguage() const;
};

/**
 * Result of applying a mutation
 */
struct MutationResult {
    bool success{false};
    std::string mutationId;
    std::string errorMessage;
    
    // Before/after metrics
    double beforeCriticalPathMs{0.0};
    double afterCriticalPathMs{0.0};
    int beforeNodeCount{0};
    int afterNodeCount{0};
    int beforeEdgeCount{0};
    int afterEdgeCount{0};
    
    // Actual impact
    double actualSpeedup{0.0};
    int64_t appliedTimestampMs{0};
    
    std::string ToJson() const;
    void PrintSummary() const;
};

/**
 * Mutation history for learning
 */
struct MutationRecord {
    SEGMutation mutation;
    MutationResult result;
    DecisionContext context;            // System state when applied
    double rewardScore{0.0};            // Learned reward
    
    std::string ToJson() const;
};

/**
 * Configuration for mutation engine
 */
struct MutationEngineConfig {
    double maxMutationRisk{0.7};          // Maximum acceptable risk
    bool requireBackupBeforeMutation{true}; // Create checkpoint first
    int maxMutationsPerCycle{3};          // Limit mutations
    double minExpectedSpeedup{0.1};       // Minimum 10% improvement
    bool enableParallelOptimization{true};
    bool enableCriticalPathOptimization{true};
    
    std::string ToJson() const;
};

/**
 * SEG Mutation Engine
 *
 * Applies autonomous decisions to modify the execution graph dynamically.
 * 
 * Example transformations:
 *   Before: A → B → C
 *   After:  A → B
 *            \   /
 *             → D → C
 */
class SEGMutationEngine {
public:
    SEGMutationEngine();
    ~SEGMutationEngine();

    // Disable copy, enable move
    SEGMutationEngine(const SEGMutationEngine&) = delete;
    SEGMutationEngine& operator=(const SEGMutationEngine&) = delete;
    SEGMutationEngine(SEGMutationEngine&&) noexcept;
    SEGMutationEngine& operator=(SEGMutationEngine&&) noexcept;

    /**
     * Initialize the mutation engine
     */
    bool Initialize(const MutationEngineConfig& config);

    /**
     * Shutdown
     */
    void Shutdown();

    /**
     * Set the execution graph to operate on
     */
    void SetExecutionGraph(std::shared_ptr<SEG::ExecutionGraph> graph);

    /**
     * Generate mutations based on a decision
     */
    std::vector<SEGMutation> GenerateMutations(const Decision& decision);

    /**
     * Apply a mutation to the execution graph
     */
    MutationResult ApplyMutation(const SEGMutation& mutation);

    /**
     * Rollback a mutation (if reversible)
     */
    bool RollbackMutation(const std::string& mutationId);

    /**
     * Preview mutation impact without applying
     */
    MutationResult PreviewMutation(const SEGMutation& mutation);

    /**
     * Get mutation history
     */
    std::vector<MutationRecord> GetMutationHistory(int count = 10) const;

    /**
     * Get statistics
     */
    struct Statistics {
        int totalMutations{0};
        int successfulMutations{0};
        int rolledBackMutations{0};
        int failedMutations{0};
        double averageSpeedup{0.0};
        double successRate{0.0};
        
        void Print() const;
    };
    Statistics GetStatistics() const;

    /**
     * Optimize for specific patterns
     */
    std::vector<SEGMutation> OptimizeForHighLoad();
    std::vector<SEGMutation> OptimizeForLowLatency();
    std::vector<SEGMutation> OptimizeForReliability();
    std::vector<SEGMutation> OptimizeForThroughput();

    /**
     * Print status
     */
    void PrintStatus() const;

private:
    // Core
    MutationEngineConfig config_;
    std::shared_ptr<SEG::ExecutionGraph> graph_;
    bool initialized_{false};
    
    // History
    std::vector<MutationRecord> history_;
    std::map<std::string, SEG::ExecutionGraph> backups_; // For rollback
    
    // Statistics
    Statistics stats_;
    
    // Mutation generators
    SEGMutation CreateReorderMutation(const std::vector<std::string>& nodes);
    SEGMutation CreateParallelPathMutation(const std::string& source, const std::string& target);
    SEGMutation CreateMergeMutation(const std::vector<std::string>& nodes);
    SEGMutation CreateSplitMutation(const std::string& node, int numParts);
    SEGMutation CreateWeightAdjustmentMutation(const std::vector<std::string>& edges, double factor);
    SEGMutation CreatePriorityMutation(const std::vector<std::string>& nodes, int priorityDelta);
    SEGMutation CreateIsolationMutation(const std::string& node);
    
    // Helpers
    double CalculateCriticalPathLength() const;
    double EstimateSpeedup(const SEGMutation& mutation) const;
    bool ValidateMutation(const SEGMutation& mutation, std::string& error) const;
    std::string GenerateMutationId() const;
    void RecordMutation(const SEGMutation& mutation, const MutationResult& result);
};

/**
 * Integration with Decision Engine
 * Converts decisions into graph mutations
 */
class DecisionToMutationAdapter {
public:
    /**
     * Convert a decision into appropriate mutations
     */
    static std::vector<SEGMutation> Adapt(const Decision& decision,
                                          SEGMutationEngine& engine);
    
private:
    static std::vector<SEGMutation> AdaptOptimizePath(const Decision& decision, SEGMutationEngine& engine);
    static std::vector<SEGMutation> AdaptSpawnWorkers(const Decision& decision, SEGMutationEngine& engine);
    static std::vector<SEGMutation> AdaptMergeTasks(const Decision& decision, SEGMutationEngine& engine);
    static std::vector<SEGMutation> AdaptRebalanceResources(const Decision& decision, SEGMutationEngine& engine);
    static std::vector<SEGMutation> AdaptFreezeComponent(const Decision& decision, SEGMutationEngine& engine);
};

} // namespace Autonomy
