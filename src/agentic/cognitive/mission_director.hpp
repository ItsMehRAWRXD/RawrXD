/**
 * @file mission_director.hpp
 * @brief Goal decomposition engine for autonomous reverse engineering
 * @description The Mission Director transforms high-level objectives (e.g., "Extract C2
 *              from this binary") into directed acyclic graphs (DAGs) of executable
 *              SubGoals. It maintains decomposition templates for common RE tasks and
 *              supports dynamic replanning based on discovered evidence.
 * @version 1.0.0
 * @date 2026-07-22
 */

#pragma once

#include "cognitive_types.hpp"
#include "enhanced_blackboard.hpp"
#include <functional>
#include <unordered_set>

namespace rawrxd::cognitive {

// ============================================================================
// Decomposition Template
// ============================================================================

struct DecompositionTemplate {
    MissionType mission_type;
    std::string name;
    std::string description;
    std::function<std::vector<SubGoal>(const std::string&, 
                                         const std::unordered_map<std::string, std::string>&)> decomposer;
    std::vector<std::string> required_capabilities;
    std::chrono::seconds estimated_duration{300};
};

// ============================================================================
// Dependency Graph
// ============================================================================

struct DependencyGraph {
    std::unordered_map<std::string, std::vector<std::string>> edges; // node -> dependents
    std::unordered_map<std::string, std::vector<std::string>> reverse_edges; // node -> dependencies
    std::vector<std::string> topological_order;
    
    bool HasCycle() const;
    std::vector<std::string> GetRoots() const;
    std::vector<std::string> GetLeaves() const;
    std::vector<std::string> GetReadyNodes(const std::unordered_set<std::string>& completed) const;
};

// ============================================================================
// Mission Director
// ============================================================================

class MissionDirector {
public:
    explicit MissionDirector(EnhancedBlackboard* blackboard);
    ~MissionDirector() = default;
    
    // Prevent copy/move
    MissionDirector(const MissionDirector&) = delete;
    MissionDirector& operator=(const MissionDirector&) = delete;
    MissionDirector(MissionDirector&&) = delete;
    MissionDirector& operator=(MissionDirector&&) = delete;
    
    // ------------------------------------------------------------------------
    // Goal Decomposition
    // ------------------------------------------------------------------------
    std::vector<SubGoal> DecomposeGoal(const std::string& goal_description,
                                        MissionType goal_type,
                                        const std::string& target_artifact,
                                        const std::unordered_map<std::string, std::string>& parameters = {});
    
    // Dynamic decomposition based on discovered features
    std::vector<SubGoal> DynamicDecompose(const std::string& parent_goal_id,
                                            const std::unordered_map<std::string, float>& discovered_features);
    
    // ------------------------------------------------------------------------
    // Replanning
    // ------------------------------------------------------------------------
    std::vector<SubGoal> Replan(const std::vector<SubGoal>& current_plan,
                                 const std::vector<std::string>& completed_ids,
                                 const std::vector<std::string>& failed_ids,
                                 const std::unordered_map<std::string, float>& new_evidence_confidences);
    
    // Inject new sub-goals into existing plan
    void InjectSubGoals(std::vector<SubGoal>& plan,
                        const std::vector<SubGoal>& new_subgoals,
                        const std::string& after_dependency);
    
    // ------------------------------------------------------------------------
    // Dependency Management
    // ------------------------------------------------------------------------
    DependencyGraph BuildDependencyGraph(const std::vector<SubGoal>& subgoals) const;
    bool ValidateDependencies(const std::vector<SubGoal>& subgoals) const;
    std::vector<std::string> FindCriticalPath(const std::vector<SubGoal>& subgoals) const;
    
    // ------------------------------------------------------------------------
    // Priority Calculation
    // ------------------------------------------------------------------------
    void RecalculatePriorities(std::vector<SubGoal>& subgoals,
                               const std::unordered_map<std::string, float>& global_confidences);
    int CalculatePriority(const SubGoal& sg,
                          const std::unordered_map<std::string, float>& global_confidences) const;
    
    // ------------------------------------------------------------------------
    // Template Management
    // ------------------------------------------------------------------------
    void RegisterTemplate(const DecompositionTemplate& templ);
    void RegisterTemplate(MissionType type,
                          const std::string& name,
                          const std::string& description,
                          std::function<std::vector<SubGoal>(const std::string&, 
                                                                 const std::unordered_map<std::string, std::string>&)> decomposer);
    bool HasTemplate(MissionType type) const;
    std::optional<DecompositionTemplate> GetTemplate(MissionType type) const;
    std::vector<DecompositionTemplate> GetAllTemplates() const;
    
    // ------------------------------------------------------------------------
    // Visualization
    // ------------------------------------------------------------------------
    std::string GenerateDependencyGraphviz(const std::vector<SubGoal>& subgoals) const;
    std::string GenerateMissionSummary(const std::vector<SubGoal>& subgoals,
                                        const std::string& mission_id) const;
    
    // ------------------------------------------------------------------------
    // Utility
    // ------------------------------------------------------------------------
    std::vector<SubGoal> FilterByStatus(const std::vector<SubGoal>& subgoals,
                                         SubGoal::Status status) const;
    std::vector<SubGoal> GetRunnableSubGoals(const std::vector<SubGoal>& subgoals) const;
    float CalculateMissionProgress(const std::vector<SubGoal>& subgoals) const;
    
private:
    EnhancedBlackboard* m_blackboard;
    std::unordered_map<MissionType, DecompositionTemplate> m_templates;
    mutable std::shared_mutex m_mutex;
    
    // Built-in decomposition templates
    void RegisterBuiltinTemplates();
    
    std::vector<SubGoal> DecomposeC2Extraction(const std::string& target,
                                                   const std::unordered_map<std::string, std::string>& params);
    std::vector<SubGoal> DecomposeMalwareClassification(const std::string& target,
                                                           const std::unordered_map<std::string, std::string>& params);
    std::vector<SubGoal> DecomposeUnpackBinary(const std::string& target,
                                                  const std::unordered_map<std::string, std::string>& params);
    std::vector<SubGoal> DecomposeProtocolReverse(const std::string& target,
                                                     const std::unordered_map<std::string, std::string>& params);
    std::vector<SubGoal> DecomposeCryptoAnalysis(const std::string& target,
                                                    const std::unordered_map<std::string, std::string>& params);
    std::vector<SubGoal> DecomposeGenericAnalysis(const std::string& target,
                                                     const std::unordered_map<std::string, std::string>& params);
    
    // Helper methods
    SubGoal CreateSubGoal(const std::string& description,
                          MissionType type,
                          const std::vector<std::string>& deps,
                          const std::vector<std::string>& capabilities,
                          int priority,
                          Confidence threshold,
                          const std::string& mission_id);
    
    bool AreDependenciesMet(const SubGoal& sg,
                            const std::unordered_set<std::string>& completed_ids) const;
    
    void UpdateDependencyGraph(DependencyGraph& graph,
                               const std::vector<SubGoal>& subgoals) const;
};

} // namespace rawrxd::cognitive
