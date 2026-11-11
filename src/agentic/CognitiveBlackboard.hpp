// ============================================================================
// CognitiveBlackboard.hpp - Working memory with hypothesis/evidence tracking
// Part of RawrXD Cognitive Foundation (Phase 1)
// Replaces simple message bus with structured cognitive state
// ============================================================================
#pragma once
#include "Evidence.hpp"
#include "Hypothesis.hpp"
#include <shared_mutex>
#include <unordered_map>
#include <vector>
#include <queue>
#include <functional>

namespace rawrxd::agentic {

// Forward declarations
class MissionDirector;
class ReflectionAgent;

// Cognitive state snapshot
struct CognitiveState {
    std::vector<Hypothesis> active_hypotheses;
    std::vector<Evidence> recent_evidence;
    std::unordered_map<std::string, float> confidence_by_domain;
    std::chrono::system_clock::time_point last_update;
    std::string current_focus;              // Most important hypothesis being worked on
    std::string current_phase;              // Current mission phase
    float mission_progress{0.0f};           // 0.0 - 1.0
    int total_evidence_count{0};
    int total_hypothesis_count{0};
    
    // Serialization
    nlohmann::json ToJson() const;
    static CognitiveState FromJson(const nlohmann::json& j);
};

// Event types for blackboard notifications
enum class BlackboardEventType {
    EVIDENCE_ADDED,
    EVIDENCE_UPDATED,
    HYPOTHESIS_CREATED,
    HYPOTHESIS_UPDATED,
    HYPOTHESIS_CONFIRMED,
    HYPOTHESIS_REFUTED,
    REPLAN_TRIGGERED,
    MISSION_PHASE_CHANGED,
    CONFIDENCE_THRESHOLD_REACHED
};

struct BlackboardEvent {
    BlackboardEventType type;
    std::string entity_id;
    std::chrono::system_clock::time_point timestamp;
    nlohmann::json payload;
};

// Callback for event notifications
typedef std::function<void(const BlackboardEvent&)> BlackboardCallback;

// Enhanced Blackboard - adds cognitive state tracking to existing message bus
class CognitiveBlackboard {
public:
    CognitiveBlackboard();
    ~CognitiveBlackboard();
    
    // Delete copy/move to ensure singleton-like behavior per orchestrator
    CognitiveBlackboard(const CognitiveBlackboard&) = delete;
    CognitiveBlackboard& operator=(const CognitiveBlackboard&) = delete;
    
    // ==================== Evidence Management ====================
    
    // Add new evidence to working memory
    std::string AddEvidence(Evidence&& ev);
    
    // Update existing evidence confidence
    void UpdateEvidenceConfidence(const std::string& id, float new_confidence);
    void UpdateEvidenceWeight(const std::string& id, float new_weight);
    
    // Retrieve evidence
    std::optional<Evidence> GetEvidence(const std::string& id) const;
    std::vector<Evidence> GetEvidenceForHypothesis(const std::string& hypothesis_id) const;
    std::vector<Evidence> GetEvidenceBySource(const std::string& agent_name) const;
    std::vector<Evidence> GetEvidenceByType(EvidenceType type) const;
    std::vector<Evidence> GetRecentEvidence(size_t count = 10) const;
    std::unordered_map<std::string, float> GetConfidenceMap() const;
    
    // ==================== Hypothesis Management ====================
    
    // Create new hypothesis
    std::string CreateHypothesis(const std::string& description, 
                                  MissionGoal goal_type,
                                  float confidence_threshold = 0.7f);
    
    // Update hypothesis with new evidence
    void UpdateHypothesis(const std::string& id, 
                          const std::vector<std::string>& supporting,
                          const std::vector<std::string>& contradicting);
    
    // Propose next action for hypothesis
    void ProposeAction(const std::string& hypothesis_id, const std::string& action);
    void SetHypothesisPriority(const std::string& id, int priority);
    
    // Retrieve hypotheses
    std::optional<Hypothesis> GetHypothesis(const std::string& id) const;
    std::vector<Hypothesis> GetActiveHypotheses() const;
    std::vector<Hypothesis> GetHypothesesByGoal(MissionGoal goal) const;
    std::vector<Hypothesis> GetHypothesesByStatus(HypothesisStatus status) const;
    std::optional<Hypothesis> GetMostConfidentHypothesis() const;
    std::optional<Hypothesis> GetHypothesisRequiringAction() const;
    std::string GetCurrentFocus() const { return m_current_focus; }
    void SetCurrentFocus(const std::string& hypothesis_id);
    
    // ==================== Cognitive State ====================
    
    CognitiveState GetCognitiveState() const;
    void UpdateCognitiveState();
    void SetMissionPhase(const std::string& phase);
    void SetMissionProgress(float progress);
    
    // ==================== Event Notifications ====================
    
    void Subscribe(BlackboardEventType event_type, BlackboardCallback callback);
    void SubscribeToAll(BlackboardCallback callback);
    void Unsubscribe(BlackboardEventType event_type);
    
    // ==================== Conflict Resolution ====================
    
    // Find and resolve conflicts between hypotheses
    std::vector<std::pair<std::string, std::string>> FindConflictingHypotheses() const;
    void ResolveConflict(const std::string& hypothesis_a, const std::string& hypothesis_b);
    
    // ==================== Pruning ====================
    
    // Remove low-confidence/old evidence and hypotheses
    void PruneLowConfidence(float threshold = 0.1f, 
                            std::chrono::hours age_limit = std::chrono::hours(24));
    void PruneRefutedHypotheses();
    
    // ==================== Statistics ====================
    
    size_t EvidenceCount() const;
    size_t HypothesisCount() const;
    size_t ActiveHypothesisCount() const;
    float AverageConfidence() const;
    
    // ==================== Serialization ====================
    
    nlohmann::json ToJson() const;
    void FromJson(const nlohmann::json& j);
    void Clear();
    
private:
    mutable std::shared_mutex m_mutex;
    
    // Core storage
    std::unordered_map<std::string, Evidence> m_evidence;
    std::unordered_map<std::string, Hypothesis> m_hypotheses;
    
    // Indexes for efficient queries
    std::unordered_map<std::string, std::vector<std::string>> m_evidence_by_source;
    std::unordered_map<EvidenceType, std::vector<std::string>> m_evidence_by_type;
    std::unordered_map<MissionGoal, std::vector<std::string>> m_hypotheses_by_goal;
    std::unordered_map<HypothesisStatus, std::vector<std::string>> m_hypotheses_by_status;
    
    // Event subscriptions
    std::unordered_map<BlackboardEventType, std::vector<BlackboardCallback>> m_subscribers;
    std::vector<BlackboardCallback> m_global_subscribers;
    
    // State
    std::string m_current_focus;
    std::string m_current_phase{"INITIALIZING"};
    float m_mission_progress{0.0f};
    std::chrono::system_clock::time_point m_last_update;
    
    // Helper methods
    void NotifySubscribers(const BlackboardEvent& event);
    void UpdateHypothesisConfidence(const std::string& hypothesis_id);
    void RebuildIndexes();
    void UpdateIndexesForEvidence(const Evidence& ev);
    void UpdateIndexesForHypothesis(const Hypothesis& hyp);
};

} // namespace rawrxd::agentic
