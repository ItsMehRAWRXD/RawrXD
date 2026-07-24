/**
 * @file autonomous_orchestrator.hpp
 * @brief Continuous mission execution loop for autonomous RE
 * @description The AutonomousOrchestrator is the top-level controller that manages
 *              the entire cognitive loop: goal decomposition → task scheduling →
 *              execution → reflection → replanning. It runs continuously until
 *              the mission is complete or cancelled.
 * @version 1.0.0
 * @date 2026-07-22
 */

#pragma once

#include "cognitive_types.hpp"
#include "enhanced_blackboard.hpp"
#include "mission_director.hpp"
#include "reflection_agent.hpp"
#include "dynamic_planner.hpp"
#include <future>

namespace rawrxd::cognitive {

// ============================================================================
// Orchestrator Configuration
// ============================================================================

struct OrchestratorConfig {
    // Timing
    std::chrono::milliseconds reflection_interval{30000}; // 30 seconds
    std::chrono::milliseconds planning_interval{5000};      // 5 seconds
    std::chrono::seconds mission_timeout{3600};             // 1 hour
    
    // Thresholds
    Confidence replan_threshold{0.3f};
    Confidence mission_success_threshold{0.8f};
    float max_failure_rate{0.5f}; // Max 50% of tasks can fail
    
    // Concurrency
    size_t max_concurrent_tasks{4};
    size_t max_replans{10}; // Prevent infinite replanning
    
    // Learning
    bool enable_learning{true};
    bool enable_pattern_extraction{true};
    bool persist_results{true};
};

// ============================================================================
// Mission Request
// ============================================================================

struct MissionRequest {
    std::string description;
    MissionType type;
    std::string target_artifact; // Binary path, memory dump, etc.
    std::unordered_map<std::string, std::string> parameters;
    OrchestratorConfig config;
    std::function<void(const MissionMetrics&)> on_complete;
    std::function<void(const std::string&)> on_progress;
};

// ============================================================================
// Autonomous Orchestrator
// ============================================================================

class AutonomousOrchestrator {
public:
    AutonomousOrchestrator();
    ~AutonomousOrchestrator();
    
    // Prevent copy/move
    AutonomousOrchestrator(const AutonomousOrchestrator&) = delete;
    AutonomousOrchestrator& operator=(const AutonomousOrchestrator&) = delete;
    AutonomousOrchestrator(AutonomousOrchestrator&&) = delete;
    AutonomousOrchestrator& operator=(AutonomousOrchestrator&&) = delete;
    
    // ------------------------------------------------------------------------
    // Initialization
    // ------------------------------------------------------------------------
    bool Initialize(const OrchestratorConfig& config = {});
    bool IsInitialized() const { return m_initialized; }
    
    // ------------------------------------------------------------------------
    // Mission Control
    // ------------------------------------------------------------------------
    std::string StartMission(const MissionRequest& request);
    void CancelMission(const std::string& mission_id);
    void CancelAllMissions();
    
    // ------------------------------------------------------------------------
    // Status
    // ------------------------------------------------------------------------
    enum class Status { IDLE, INITIALIZING, PLANNING, EXECUTING, REFLECTING, COMPLETE, CANCELLED, FAILED };
    Status GetStatus() const { return m_status.load(); }
    std::string GetStatusString() const;
    
    float GetMissionProgress(const std::string& mission_id) const;
    std::string GetCurrentPhase(const std::string& mission_id) const;
    CognitiveState GetCognitiveState() const;
    
    // ------------------------------------------------------------------------
    // Results
    // ------------------------------------------------------------------------
    std::optional<MissionMetrics> GetMissionMetrics(const std::string& mission_id) const;
    std::vector<MissionMetrics> GetAllMissionMetrics() const;
    std::string GenerateMissionReport(const std::string& mission_id) const;
    
    // ------------------------------------------------------------------------
    // Component Access (for advanced use)
    // ------------------------------------------------------------------------
    EnhancedBlackboard* GetBlackboard() const { return m_blackboard.get(); }
    MissionDirector* GetMissionDirector() const { return m_director.get(); }
    ReflectionAgent* GetReflectionAgent() const { return m_reflector.get(); }
    DynamicPlanner* GetPlanner() const { return m_planner.get(); }
    
    // ------------------------------------------------------------------------
    // Utility
    // ------------------------------------------------------------------------
    void WaitForMission(const std::string& mission_id);
    void WaitForAllMissions();
    void Shutdown();
    
private:
    // Core components
    std::unique_ptr<EnhancedBlackboard> m_blackboard;
    std::unique_ptr<MissionDirector> m_director;
    std::unique_ptr<ReflectionAgent> m_reflector;
    std::unique_ptr<DynamicPlanner> m_planner;
    
    // State
    std::atomic<bool> m_initialized{false};
    std::atomic<bool> m_running{false};
    std::atomic<Status> m_status{Status::IDLE};
    OrchestratorConfig m_config;
    
    // Mission tracking
    std::unordered_map<std::string, std::future<void>> m_mission_futures;
    std::unordered_map<std::string, MissionRequest> m_active_requests;
    mutable std::mutex m_mission_mutex;
    
    // Statistics
    int m_total_missions{0};
    int m_completed_missions{0};
    int m_failed_missions{0};
    int m_cancelled_missions{0};
    
    // Main mission loop
    void MissionLoop(const std::string& mission_id, const MissionRequest& request);
    
    // Phase handlers
    void PlanningPhase(const std::string& mission_id, std::vector<SubGoal>& plan);
    void ExecutionPhase(const std::string& mission_id, std::vector<SubGoal>& plan);
    void ReflectionPhase(const std::string& mission_id, std::vector<SubGoal>& plan);
    bool ReplanningPhase(const std::string& mission_id, std::vector<SubGoal>& plan);
    
    // Helpers
    bool IsMissionComplete(const std::vector<SubGoal>& plan) const;
    bool IsMissionFailed(const std::vector<SubGoal>& plan) const;
    bool IsMissionTimedOut(const std::string& mission_id) const;
    void UpdateMissionMetrics(const std::string& mission_id, const std::vector<SubGoal>& plan);
    void NotifyProgress(const std::string& mission_id, const std::string& message);
};

} // namespace rawrxd::cognitive
