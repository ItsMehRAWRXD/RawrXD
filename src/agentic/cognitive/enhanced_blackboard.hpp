/**
 * @file enhanced_blackboard.hpp
 * @brief Working memory with cognitive state tracking
 * @description Extends the traditional message-passing Blackboard with structured
 *              hypothesis/evidence storage, confidence management, and conflict
 *              resolution. This is the shared cognitive workspace for all agents.
 * @version 1.0.0
 * @date 2026-07-22
 */

#pragma once

#include "cognitive_types.hpp"
#include <shared_mutex>
#include <condition_variable>
#include <queue>
#include <functional>

namespace rawrxd::cognitive {

// ============================================================================
// Blackboard Event Types
// ============================================================================

enum class BlackboardEvent {
    EVIDENCE_ADDED,
    EVIDENCE_UPDATED,
    HYPOTHESIS_CREATED,
    HYPOTHESIS_UPDATED,
    HYPOTHESIS_CONFIRMED,
    HYPOTHESIS_REFUTED,
    TASK_SCHEDULED,
    TASK_COMPLETED,
    TASK_FAILED,
    REPLAN_TRIGGERED,
    MISSION_STARTED,
    MISSION_COMPLETE,
    AGENT_REGISTERED,
    AGENT_UNREGISTERED
};

// ============================================================================
// Event Callback
// ============================================================================

using BlackboardCallback = std::function<void(BlackboardEvent, const std::string&)>;

// ============================================================================
// Enhanced Blackboard - Cognitive Working Memory
// ============================================================================

class EnhancedBlackboard {
public:
    EnhancedBlackboard();
    ~EnhancedBlackboard();
    
    // Prevent copy/move
    EnhancedBlackboard(const EnhancedBlackboard&) = delete;
    EnhancedBlackboard& operator=(const EnhancedBlackboard&) = delete;
    EnhancedBlackboard(EnhancedBlackboard&&) = delete;
    EnhancedBlackboard& operator=(EnhancedBlackboard&&) = delete;
    
    // ------------------------------------------------------------------------
    // Evidence Management
    // ------------------------------------------------------------------------
    std::string AddEvidence(Evidence&& evidence);
    void UpdateEvidenceConfidence(const std::string& id, Confidence new_confidence);
    void UpdateEvidenceWeight(const std::string& id, float new_weight);
    std::optional<Evidence> GetEvidence(const std::string& id) const;
    std::vector<Evidence> GetEvidenceForHypothesis(const std::string& hypothesis_id) const;
    std::vector<Evidence> GetEvidenceByAgent(const std::string& agent_name) const;
    std::vector<Evidence> GetRecentEvidence(size_t count = 10) const;
    std::unordered_map<std::string, Confidence> GetConfidenceMap() const;
    size_t EvidenceCount() const;
    void RemoveEvidence(const std::string& id);
    void ClearEvidence();
    
    // ------------------------------------------------------------------------
    // Hypothesis Management
    // ------------------------------------------------------------------------
    std::string CreateHypothesis(const std::string& claim, 
                                  const std::string& domain,
                                  const std::string& mission_id,
                                  int priority = 50);
    void UpdateHypothesisConfidence(const std::string& id, Confidence confidence);
    void AddEvidenceToHypothesis(const std::string& hypothesis_id, 
                                  const std::string& evidence_id,
                                  bool supporting);
    void UpdateHypothesisStatus(const std::string& id, Hypothesis::Status status);
    void ProposeAction(const std::string& hypothesis_id, const std::string& action);
    std::optional<Hypothesis> GetHypothesis(const std::string& id) const;
    std::vector<Hypothesis> GetActiveHypotheses() const;
    std::vector<Hypothesis> GetHypothesesByDomain(const std::string& domain) const;
    std::vector<Hypothesis> GetHypothesesByMission(const std::string& mission_id) const;
    std::optional<Hypothesis> GetMostConfidentHypothesis() const;
    std::optional<Hypothesis> GetHighestPriorityHypothesis() const;
    size_t HypothesisCount() const;
    void RemoveHypothesis(const std::string& id);
    void ClearHypotheses();
    
    // ------------------------------------------------------------------------
    // Task Management
    // ------------------------------------------------------------------------
    void ScheduleTask(Task&& task);
    std::optional<Task> GetNextTask();
    void MarkTaskComplete(const std::string& task_id, 
                          const std::unordered_map<std::string, float>& results);
    void MarkTaskFailed(const std::string& task_id, const std::string& reason);
    std::optional<Task> GetTask(const std::string& task_id) const;
    std::vector<Task> GetPendingTasks() const;
    std::vector<Task> GetActiveTasks() const;
    std::vector<Task> GetCompletedTasks() const;
    std::vector<Task> GetFailedTasks() const;
    size_t PendingTaskCount() const;
    size_t ActiveTaskCount() const;
    void ClearTasks();
    
    // ------------------------------------------------------------------------
    // Agent Performance Tracking
    // ------------------------------------------------------------------------
    void RegisterAgent(const std::string& agent_name, 
                       const std::vector<Capability>& capabilities);
    void UnregisterAgent(const std::string& agent_name);
    void RecordAgentSuccess(const std::string& agent_name, 
                            const std::string& capability,
                            Confidence confidence,
                            float duration_ms);
    void RecordAgentFailure(const std::string& agent_name,
                            const std::string& capability,
                            const std::string& reason);
    std::optional<AgentPerformance> GetAgentPerformance(const std::string& agent_name) const;
    std::vector<AgentPerformance> GetAllAgentPerformance() const;
    std::vector<std::string> FindAgentsWithCapability(const std::string& capability) const;
    
    // ------------------------------------------------------------------------
    // Cognitive State
    // ------------------------------------------------------------------------
    CognitiveState GetCognitiveState() const;
    void UpdateCognitiveState();
    std::string GetCurrentFocus() const;
    void SetCurrentFocus(const std::string& hypothesis_id);
    std::string GetCurrentPhase() const;
    void SetCurrentPhase(const std::string& phase);
    
    // ------------------------------------------------------------------------
    // Event Subscription
    // ------------------------------------------------------------------------
    void Subscribe(BlackboardEvent event, BlackboardCallback callback);
    void Unsubscribe(BlackboardEvent event);
    void Notify(BlackboardEvent event, const std::string& details);
    
    // ------------------------------------------------------------------------
    // Mission Management
    // ------------------------------------------------------------------------
    void StartMission(const std::string& mission_id, 
                      const std::string& description,
                      MissionType type);
    void CompleteMission(const std::string& mission_id);
    void FailMission(const std::string& mission_id, const std::string& reason);
    std::optional<MissionMetrics> GetMissionMetrics(const std::string& mission_id) const;
    std::vector<MissionMetrics> GetAllMissionMetrics() const;
    
    // ------------------------------------------------------------------------
    // Utility
    // ------------------------------------------------------------------------
    void ClearAll();
    std::string DumpState() const;  // For debugging/logging
    void PruneLowConfidence(Confidence threshold = 0.1f);
    void PruneOldEvidence(std::chrono::hours age_limit = std::chrono::hours(24));
    
private:
    // Data stores
    std::unordered_map<std::string, Evidence> m_evidence;
    std::unordered_map<std::string, Hypothesis> m_hypotheses;
    std::priority_queue<Task> m_task_queue;
    std::unordered_map<std::string, Task> m_active_tasks;
    std::unordered_map<std::string, Task> m_completed_tasks;
    std::unordered_map<std::string, Task> m_failed_tasks;
    std::unordered_map<std::string, AgentPerformance> m_agent_performance;
    std::unordered_map<std::string, std::vector<Capability>> m_agent_capabilities;
    std::unordered_map<std::string, MissionMetrics> m_mission_metrics;
    
    // Cognitive state
    std::string m_current_focus;
    std::string m_current_phase{"IDLE"};
    std::chrono::system_clock::time_point m_last_update;
    int m_total_reflections{0};
    int m_total_replans{0};
    
    // Event system
    std::unordered_map<BlackboardEvent, std::vector<BlackboardCallback>> m_callbacks;
    
    // Synchronization
    mutable std::shared_mutex m_mutex;
    std::condition_variable_any m_task_cv;
    
    // Internal helpers
    void ResolveConflicts(const std::string& hypothesis_id);
    Confidence RecalculateHypothesisConfidence(const std::string& hypothesis_id);
    void UpdateHypothesisTimestamp(const std::string& id);
    void EmitEvent(BlackboardEvent event, const std::string& details);
};

} // namespace rawrxd::cognitive
