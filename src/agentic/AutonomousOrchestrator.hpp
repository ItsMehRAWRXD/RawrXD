// ============================================================================
// AutonomousOrchestrator.hpp - Continuous mission execution loop
// Part of RawrXD Cognitive Foundation (Phase 1)
// Replaces linear phase execution with autonomous goal-pursuit
// ============================================================================
#pragma once
#include "CognitiveBlackboard.hpp"
#include "MissionDirector.hpp"
#include "ReflectionAgent.hpp"
#include "DynamicPlanner.hpp"
#include <memory>
#include <atomic>
#include <thread>

namespace rawrxd::agentic {

// Forward declarations
class ToolRegistry;
class AgentPool;
class KnowledgeGraph;

// Orchestrator status
enum class OrchestratorStatus {
    IDLE,           // Waiting for mission
    INITIALIZING,   // Setting up mission
    PLANNING,       // Decomposing goals
    EXECUTING,      // Running tasks
    REFLECTING,     // Evaluating results
    REPLANNING,     // Adjusting plan
    COMPLETE,       // Mission finished successfully
    FAILED,         // Mission failed
    CANCELLED       // Mission cancelled by user
};

// Mission configuration
struct MissionConfig {
    // Execution
    int max_parallel_tasks{4};
    std::chrono::minutes mission_timeout{std::chrono::minutes(60)};
    bool enable_auto_replan{true};
    float replan_confidence_threshold{0.3f};
    
    // Reflection
    bool enable_continuous_reflection{true};
    std::chrono::seconds reflection_interval{std::chrono::seconds(30)};
    float confidence_confirmation_threshold{0.8f};
    
    // Learning
    bool enable_pattern_learning{true};
    bool enable_agent_weighting{true};
    
    // Debugging
    bool verbose_logging{false};
    bool save_execution_trace{true};
};

// Mission state snapshot
struct MissionState {
    std::string mission_id;
    std::string goal_description;
    MissionGoal goal_type;
    OrchestratorStatus status{OrchestratorStatus::IDLE};
    float progress{0.0f};
    float overall_confidence{0.0f};
    std::string current_phase;
    std::string current_focus;          // Current hypothesis being pursued
    std::chrono::system_clock::time_point start_time;
    std::chrono::system_clock::time_point estimated_end;
    std::vector<std::string> active_tasks;
    std::vector<std::string> completed_tasks;
    std::vector<std::string> failed_tasks;
    int replan_count{0};
    int reflection_count{0};
};

// Mission result
struct MissionResult {
    bool success{false};
    std::string mission_id;
    std::chrono::system_clock::time_point start_time;
    std::chrono::system_clock::time_point end_time;
    std::chrono::milliseconds duration{0};
    
    // Results
    std::vector<std::string> findings;
    std::vector<std::string> confirmed_hypotheses;
    std::vector<std::string> refuted_hypotheses;
    std::vector<std::string> unresolved_questions;
    
    // Evidence
    std::vector<Evidence> key_evidence;
    std::vector<Hypothesis> final_hypotheses;
    
    // Statistics
    int total_tasks{0};
    int completed_tasks{0};
    int failed_tasks{0};
    int replan_count{0};
    float final_confidence{0.0f};
    
    // Artifacts
    std::unordered_map<std::string, std::string> generated_artifacts;
    std::string execution_trace_path;
};

// Progress callback
typedef std::function<void(const MissionState&)> ProgressCallback;

// AutonomousOrchestrator - Continuous mission execution loop
class AutonomousOrchestrator {
public:
    AutonomousOrchestrator();
    ~AutonomousOrchestrator();
    
    // Delete copy/move
    AutonomousOrchestrator(const AutonomousOrchestrator&) = delete;
    AutonomousOrchestrator& operator=(const AutonomousOrchestrator&) = delete;
    
    // ==================== Initialization ====================
    
    // Initialize with optional external components
    void Initialize(ToolRegistry* tools = nullptr,
                   AgentPool* agents = nullptr,
                   KnowledgeGraph* kg = nullptr);
    
    bool IsInitialized() const { return m_initialized.load(); }
    
    // ==================== Mission Control ====================
    
    // Start a new mission (non-blocking)
    std::string StartMission(const std::string& goal_description,
                            MissionGoal goal_type,
                            const MissionContext& context = {},
                            const MissionConfig& config = {});
    
    // Start and wait for completion (blocking)
    MissionResult ExecuteMission(const std::string& goal_description,
                                MissionGoal goal_type,
                                const MissionContext& context = {},
                                const MissionConfig& config = {});
    
    // Cancel current mission
    void CancelMission(const std::string& reason = "User requested");
    
    // Pause/Resume
    void Pause();
    void Resume();
    
    // ==================== Status Queries ====================
    
    OrchestratorStatus GetStatus() const { return m_status.load(); }
    MissionState GetMissionState() const;
    float GetMissionProgress() const;
    std::string GetCurrentPhase() const;
    std::string GetCurrentFocus() const;
    
    // Check if mission is active
    bool IsMissionActive() const;
    bool IsMissionComplete() const;
    
    // ==================== Results ====================
    
    // Get mission result (only valid after completion)
    MissionResult GetMissionResult() const;
    
    // Wait for mission completion
    bool WaitForCompletion(std::chrono::milliseconds timeout = std::chrono::milliseconds(-1));
    
    // ==================== Callbacks ====================
    
    void SetProgressCallback(ProgressCallback callback);
    void SetCompletionCallback(std::function<void(const MissionResult&)> callback);
    
    // ==================== Configuration ====================
    
    void SetDefaultConfig(const MissionConfig& config);
    MissionConfig GetDefaultConfig() const;
    
    // ==================== Component Access ====================
    
    CognitiveBlackboard* GetBlackboard() const { return m_blackboard.get(); }
    MissionDirector* GetMissionDirector() const { return m_director.get(); }
    ReflectionAgent* GetReflectionAgent() const { return m_reflector.get(); }
    DynamicPlanner* GetPlanner() const { return m_planner.get(); }
    
    // ==================== Statistics ====================
    
    struct OrchestratorStats {
        int total_missions{0};
        int successful_missions{0};
        int failed_missions{0};
        int cancelled_missions{0};
        std::chrono::milliseconds total_execution_time{0};
        float average_mission_confidence{0.0f};
        int total_replans{0};
        int total_reflections{0};
    };
    OrchestratorStats GetStats() const;
    void ResetStats();
    
    // ==================== Persistence ====================
    
    // Save mission state for resumption
    void SaveCheckpoint(const std::string& path);
    bool LoadCheckpoint(const std::string& path);
    
    // Export execution trace
    void ExportExecutionTrace(const std::string& path) const;
    
private:
    // Core components
    std::unique_ptr<CognitiveBlackboard> m_blackboard;
    std::unique_ptr<MissionDirector> m_director;
    std::unique_ptr<ReflectionAgent> m_reflector;
    std::unique_ptr<DynamicPlanner> m_planner;
    std::unique_ptr<ToolRegistry> m_tool_registry;
    std::unique_ptr<AgentPool> m_agent_pool;
    std::unique_ptr<KnowledgeGraph> m_knowledge_graph;
    
    // State
    std::atomic<bool> m_initialized{false};
    std::atomic<OrchestratorStatus> m_status{OrchestratorStatus::IDLE};
    std::atomic<bool> m_running{false};
    std::atomic<bool> m_paused{false};
    std::atomic<bool> m_cancelled{false};
    
    // Mission state
    std::string m_current_mission_id;
    std::string m_goal_description;
    MissionGoal m_goal_type{MissionGoal::UNKNOWN};
    MissionConfig m_config;
    MissionContext m_context;
    MissionResult m_result;
    std::vector<SubGoal> m_current_plan;
    std::unordered_map<std::string, float> m_global_confidences;
    
    // Threading
    std::thread m_mission_thread;
    mutable std::mutex m_state_mutex;
    std::condition_variable m_completion_cv;
    
    // Callbacks
    ProgressCallback m_progress_callback;
    std::function<void(const MissionResult&)> m_completion_callback;
    std::mutex m_callback_mutex;
    
    // Statistics
    OrchestratorStats m_stats;
    mutable std::mutex m_stats_mutex;
    
    // Main mission loop
    void MissionLoop();
    void ExecuteTask(const ScheduledTask& task);
    void ProcessResults(const std::string& task_id,
                       const std::unordered_map<std::string, float>& results);
    void HandleReplan(ReplanReason reason);
    bool CheckMissionComplete();
    void UpdateMissionState();
    void NotifyProgress();
    void NotifyCompletion();
    
    // Helper methods
    void InitializeComponents();
    void CleanupMission();
    float CalculateOverallConfidence() const;
    std::string GenerateMissionId() const;
};

} // namespace rawrxd::agentic
