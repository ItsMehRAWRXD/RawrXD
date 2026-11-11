// ============================================================================
// MissionDirector.hpp - Goal decomposition and dynamic replanning engine
// Part of RawrXD Cognitive Foundation (Phase 1)
// ============================================================================
#pragma once
#include "CognitiveBlackboard.hpp"
#include "SubGoal.hpp"
#include <functional>
#include <memory>

namespace rawrxd::agentic {

// Forward declarations
class KnowledgeGraph;
class ToolRegistry;

// Goal decomposition result
struct DecompositionResult {
    std::vector<SubGoal> subgoals;
    std::vector<Hypothesis> initial_hypotheses;
    std::unordered_map<std::string, std::string> parameters;
    std::string root_hypothesis_id;
    bool success{false};
    std::string error_message;
};

// Replanning trigger reasons
enum class ReplanReason {
    CONFIDENCE_DROP,         // Hypothesis confidence fell below threshold
    EVIDENCE_CONTRADICTION,  // New evidence contradicts current plan
    AGENT_FAILURE,           // Agent execution failed
    NEW_INFORMATION,         // Unexpected discovery requiring adaptation
    TIMEOUT,                 // Sub-goal exceeded timeout
    USER_REQUEST             // Manual replanning request
};

// Mission context for decomposition
struct MissionContext {
    std::string binary_path;
    std::unordered_map<std::string, std::string> file_metadata;
    std::vector<std::string> available_agents;
    std::vector<std::string> available_tools;
    std::unordered_map<std::string, float> initial_confidences;
    int max_parallel_tasks{4};
    std::chrono::minutes mission_timeout{std::chrono::minutes(60)};
};

// Mission Director - Decomposes high-level goals into executable sub-goals
class MissionDirector {
public:
    MissionDirector(CognitiveBlackboard* bb, 
                   KnowledgeGraph* kg = nullptr,
                   ToolRegistry* tools = nullptr);
    ~MissionDirector() = default;
    
    // Delete copy/move
    MissionDirector(const MissionDirector&) = delete;
    MissionDirector& operator=(const MissionDirector&) = delete;
    
    // ==================== Goal Decomposition ====================
    
    // Main entry point - decompose a high-level goal into sub-goals
    DecompositionResult DecomposeGoal(const std::string& goal_description,
                                        MissionGoal goal_type,
                                        const MissionContext& context);
    
    // Specialized decompositions for common RE goals
    DecompositionResult DecomposeC2Extraction(const MissionContext& ctx);
    DecompositionResult DecomposeMalwareClassification(const MissionContext& ctx);
    DecompositionResult DecomposeProtocolReverse(const MissionContext& ctx);
    DecompositionResult DecomposeUnpacking(const MissionContext& ctx);
    DecompositionResult DecomposeCryptoAnalysis(const MissionContext& ctx);
    DecompositionResult DecomposeVulnerabilityDiscovery(const MissionContext& ctx);
    
    // Dynamic decomposition - adapt based on discovered features
    DecompositionResult DynamicDecompose(
        const std::string& goal,
        const std::unordered_map<std::string, float>& discovered_features,
        const MissionContext& context);
    
    // ==================== Replanning ====================
    
    // Replan based on new information
    std::vector<SubGoal> Replan(const std::vector<SubGoal>& current_plan,
                                const std::vector<std::string>& completed_ids,
                                const std::vector<std::string>& failed_ids,
                                const std::unordered_map<std::string, float>& new_confidences,
                                ReplanReason reason);
    
    // Generate alternative approaches for failed sub-goals
    std::vector<SubGoal> GenerateAlternatives(const SubGoal& failed_subgoal);
    
    // Adjust priorities based on mission progress
    void AdjustPriorities(std::vector<SubGoal>& subgoals,
                         const std::unordered_map<std::string, float>& global_confidences);
    
    // ==================== Validation ====================
    
    // Validate that all required capabilities exist
    bool ValidateCapabilities(const SubGoal& sg, 
                             const std::vector<std::string>& available_capabilities);
    
    // Check if plan is executable
    bool IsPlanExecutable(const std::vector<SubGoal>& plan,
                         const std::vector<std::string>& available_capabilities);
    
    // Find missing capabilities
    std::vector<CapabilityRequirement> FindMissingCapabilities(
        const std::vector<SubGoal>& plan,
        const std::vector<std::string>& available_capabilities);
    
    // ==================== Visualization ====================
    
    // Generate dependency graph in DOT format for visualization
    std::string GenerateDependencyGraph(const std::vector<SubGoal>& subgoals);
    
    // Generate mission summary
    std::string GenerateMissionSummary(const std::vector<SubGoal>& subgoals,
                                       const std::vector<Hypothesis>& hypotheses);
    
    // ==================== Templates ====================
    
    // Register custom decomposition template
    using DecompositionTemplate = std::function<DecompositionResult(const MissionContext&)>;
    void RegisterTemplate(MissionGoal goal, DecompositionTemplate tmpl);
    
    // Get registered templates
    std::vector<MissionGoal> GetRegisteredTemplates() const;
    
private:
    CognitiveBlackboard* m_blackboard;
    KnowledgeGraph* m_knowledge_graph;
    ToolRegistry* m_tool_registry;
    
    // Template registry
    std::unordered_map<MissionGoal, DecompositionTemplate> m_templates;
    
    // Helper methods
    int CalculatePriority(const SubGoal& sg,
                         const std::unordered_map<std::string, float>& global_confidences);
    void BuildDependencyGraph(std::vector<SubGoal>& subgoals);
    std::vector<SubGoal> MergeWithExisting(const std::vector<SubGoal>& new_plan,
                                            const std::vector<SubGoal>& existing);
    
    // Template implementations
    void InitializeDefaultTemplates();
    
    // C2 extraction template
    DecompositionResult TemplateC2Extraction(const MissionContext& ctx);
    
    // Malware classification template
    DecompositionResult TemplateMalwareClassification(const MissionContext& ctx);
    
    // Protocol reverse template
    DecompositionResult TemplateProtocolReverse(const MissionContext& ctx);
    
    // Unpacking template
    DecompositionResult TemplateUnpacking(const MissionContext& ctx);
    
    // Crypto analysis template
    DecompositionResult TemplateCryptoAnalysis(const MissionContext& ctx);
    
    // Vulnerability discovery template
    DecompositionResult TemplateVulnerabilityDiscovery(const MissionContext& ctx);
};

} // namespace rawrxd::agentic
