// ============================================================================
// SubGoal.hpp - Decomposed task with dependencies and capabilities
// Part of RawrXD Cognitive Foundation (Phase 1)
// ============================================================================
#pragma once
#include "Hypothesis.hpp"
#include <string>
#include <vector>
#include <unordered_set>
#include <chrono>
#include <optional>

namespace rawrxd::agentic {

// Sub-goal status
enum class SubGoalStatus {
    PENDING,         // Waiting for dependencies
    READY,           // Dependencies met, ready to execute
    IN_PROGRESS,     // Currently being executed
    COMPLETE,        // Successfully completed
    FAILED,          // Execution failed
    BLOCKED,         // Blocked by failure or missing capability
    CANCELLED        // Cancelled by user or replanning
};

// Capability requirement
struct CapabilityRequirement {
    std::string capability_name;
    int min_version{1};
    std::unordered_map<std::string, std::string> parameters;
    bool optional{false};  // If true, can proceed without this capability
};

// SubGoal - a decomposed task with dependencies and requirements
struct SubGoal {
    std::string id;
    std::string description;
    MissionGoal mission_type{MissionGoal::UNKNOWN};
    SubGoalStatus status{SubGoalStatus::PENDING};
    
    // Dependencies - other sub-goals that must complete first
    std::vector<std::string> dependencies;  // IDs of prerequisite sub-goals
    std::vector<std::string> blocks;          // IDs of sub-goals this blocks
    
    // Capability requirements
    std::vector<CapabilityRequirement> required_capabilities;
    std::vector<std::string> preferred_agents;  // Agent names that can execute this
    
    // Execution parameters
    std::unordered_map<std::string, std::string> parameters;
    std::unordered_map<std::string, nlohmann::json> structured_parameters;
    
    // Priority and scheduling
    int base_priority{50};           // 0-100, set by mission director
    int dynamic_priority{0};         // Adjusted by planner based on context
    int final_priority() const { return base_priority + dynamic_priority; }
    std::chrono::seconds estimated_duration{std::chrono::seconds(60)};
    std::chrono::seconds timeout{std::chrono::seconds(300)};
    
    // Confidence thresholds
    float confidence_threshold{0.7f};    // Minimum confidence to consider complete
    float current_confidence{0.0f};      // Current confidence from execution
    
    // Associated hypothesis
    std::string target_hypothesis_id;    // Hypothesis this sub-goal works toward
    std::vector<std::string> expected_evidence;  // Evidence types expected to produce
    
    // Execution tracking
    std::string assigned_agent;
    std::chrono::system_clock::time_point assigned_at;
    std::chrono::system_clock::time_point started_at;
    std::chrono::system_clock::time_point completed_at;
    int retry_count{0};
    int max_retries{3};
    
    // Results
    std::string result_summary;
    std::vector<std::string> produced_evidence;
    std::optional<nlohmann::json> structured_result;
    
    // Failure handling
    std::string failure_reason;
    std::vector<std::string> fallback_subgoals;  // Alternative approaches
    
    // Constructors
    SubGoal() = default;
    SubGoal(const std::string& desc, MissionGoal type, int priority = 50);
    
    // Generate unique ID
    static std::string GenerateId();
    
    // Check if dependencies are met (given a set of completed IDs)
    bool AreDependenciesMet(const std::unordered_set<std::string>& completed) const;
    
    // Check if this sub-goal is runnable
    bool IsRunnable(const std::unordered_set<std::string>& completed,
                  const std::vector<std::string>& available_capabilities) const;
    
    // Update status
    void Start(const std::string& agent_name);
    void Complete(float confidence, const std::string& summary);
    void Fail(const std::string& reason);
    void Block();
    void Unblock();
    bool CanRetry() const { return retry_count < max_retries; }
    
    // Serialization
    nlohmann::json ToJson() const;
    static SubGoal FromJson(const nlohmann::json& j);
};

// SubGoal utilities
class SubGoalUtils {
public:
    // Build dependency graph from sub-goals
    static std::unordered_map<std::string, std::vector<std::string>> 
        BuildDependencyGraph(const std::vector<SubGoal>& subgoals);
    
    // Topological sort for execution order
    static std::vector<std::string> TopologicalSort(
        const std::vector<SubGoal>& subgoals);
    
    // Find critical path (longest dependency chain)
    static std::vector<std::string> FindCriticalPath(
        const std::vector<SubGoal>& subgoals);
    
    // Calculate parallel execution potential
    static int CalculateParallelism(const std::vector<SubGoal>& subgoals);
    
    // Find ready sub-goals given current state
    static std::vector<std::string> FindReadySubGoals(
        const std::vector<SubGoal>& subgoals,
        const std::unordered_set<std::string>& completed);
    
    // Mission goal to default sub-goal template
    static std::vector<SubGoal> GetTemplateForGoal(MissionGoal goal);
};

} // namespace rawrxd::agentic
