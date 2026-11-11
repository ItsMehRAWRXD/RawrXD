// ============================================================================
// ReflectionAgent.hpp - Self-evaluation and continuous improvement
// Part of RawrXD Cognitive Foundation (Phase 1)
// ============================================================================
#pragma once
#include "CognitiveBlackboard.hpp"
#include "MissionDirector.hpp"
#include <atomic>
#include <thread>
#include <queue>

namespace rawrxd::agentic {

// Forward declarations
class KnowledgeGraph;
class DynamicPlanner;

// Reflection event types
enum class ReflectionEventType {
    PHASE_COMPLETE,
    AGENT_RESULT,
    HYPOTHESIS_UPDATED,
    EVIDENCE_CONTRADICTS,
    CONFIDENCE_THRESHOLD_REACHED,
    TIMEOUT_OCCURRED,
    ANOMALY_DETECTED
};

struct ReflectionEvent {
    ReflectionEventType type;
    std::string entity_id;
    std::chrono::system_clock::time_point timestamp;
    nlohmann::json context;
};

// Confidence scoring configuration
struct ConfidenceConfig {
    float evidence_weight{0.3f};           // Weight of individual evidence
    float source_reliability_weight{0.2f}; // Weight of source agent reliability
    float consistency_weight{0.3f};      // Weight of internal consistency
    float prior_weight{0.2f};              // Weight of prior probability
    float min_confidence_threshold{0.1f};  // Below this, evidence is discarded
    float replan_threshold{0.3f};          // Below this, trigger replanning
    float confirmation_threshold{0.8f};      // Above this, hypothesis is confirmed
};

// Agent performance metrics
struct AgentPerformance {
    std::string agent_name;
    int tasks_attempted{0};
    int tasks_succeeded{0};
    int tasks_failed{0};
    float average_confidence{0.0f};
    std::chrono::milliseconds average_execution_time{0};
    std::chrono::milliseconds total_execution_time{0};
    std::vector<float> confidence_history;
    float current_weight{1.0f};            // Dynamic weight based on performance
    
    float SuccessRate() const {
        return tasks_attempted > 0 ? static_cast<float>(tasks_succeeded) / tasks_attempted : 0.0f;
    }
};

// Reflection result
struct ReflectionResult {
    bool replan_recommended{false};
    std::string reason;
    std::vector<std::string> affected_hypotheses;
    std::vector<std::string> suggested_actions;
    float confidence_adjustment{0.0f};
    std::unordered_map<std::string, float> agent_weight_adjustments;
};

// Pattern extracted from evidence
struct DiscoveredPattern {
    std::string pattern_type;              // e.g., "packer_signature", "api_sequence"
    std::string description;
    std::vector<std::string> evidence_ids;
    float confidence{0.0f};
    int occurrence_count{1};
    std::chrono::system_clock::time_point first_seen;
    std::chrono::system_clock::time_point last_seen;
};

// Reflection Agent - Evaluates results and triggers replanning
class ReflectionAgent {
public:
    ReflectionAgent(CognitiveBlackboard* bb,
                   MissionDirector* director,
                   KnowledgeGraph* kg = nullptr,
                   DynamicPlanner* planner = nullptr);
    ~ReflectionAgent();
    
    // Delete copy/move
    ReflectionAgent(const ReflectionAgent&) = delete;
    ReflectionAgent& operator=(const ReflectionAgent&) = delete;
    
    // ==================== Lifecycle ====================
    
    void Start();                          // Start reflection thread
    void Stop();                           // Stop reflection thread
    bool IsRunning() const { return m_running.load(); }
    
    // ==================== Event-Driven Reflection ====================
    
    // Triggered after each significant event (called by other agents/components)
    void OnPhaseComplete(const std::string& phase_name,
                        const std::unordered_map<std::string, float>& results);
    void OnAgentResult(const std::string& agent_name,
                      const std::string& task_id,
                      const std::unordered_map<std::string, float>& results,
                      bool success);
    void OnHypothesisUpdated(const std::string& hypothesis_id);
    void OnEvidenceContradicts(const std::string& evidence_id,
                              const std::string& hypothesis_id);
    void OnTimeout(const std::string& task_id);
    void OnAnomalyDetected(const std::string& context,
                          const std::string& description);
    
    // ==================== Confidence Scoring ====================
    
    // Calculate confidence for a hypothesis based on evidence
    float ScoreHypothesisConfidence(const Hypothesis& hypothesis,
                                   const std::vector<Evidence>& evidence);
    
    // Calculate confidence for mission based on completed sub-goals
    float ScoreMissionConfidence(const std::vector<SubGoal>& completed_subgoals);
    
    // Calculate source reliability
    float ScoreSourceReliability(const std::string& agent_name);
    
    // Check consistency between evidence
    float ScoreEvidenceConsistency(const std::vector<Evidence>& evidence);
    
    // ==================== Replanning Decisions ====================
    
    // Determine if replanning is needed
    bool ShouldReplan(const std::vector<SubGoal>& current_plan,
                     const std::vector<Hypothesis>& hypotheses);
    
    // Generate replanning recommendation
    ReflectionResult GenerateReplanRecommendation(
        const std::vector<SubGoal>& current_plan,
        const std::vector<Hypothesis>& hypotheses);
    
    // Trigger immediate replanning
    void TriggerReplan(const std::string& reason);
    
    // ==================== Learning ====================
    
    // Extract patterns from evidence
    std::vector<DiscoveredPattern> ExtractPatterns(
        const std::vector<Evidence>& evidence);
    
    // Update agent weightings based on performance
    void UpdateAgentWeightings();
    
    // Get agent performance metrics
    std::unordered_map<std::string, AgentPerformance> GetAgentPerformance() const;
    
    // Store successful pattern for future reuse
    void StorePattern(const DiscoveredPattern& pattern);
    
    // Retrieve relevant patterns for current mission
    std::vector<DiscoveredPattern> RetrieveRelevantPatterns(
        const std::string& context);
    
    // ==================== Anomaly Detection ====================
    
    // Detect anomalies in execution
    std::vector<std::string> DetectAnomalies(
        const std::vector<SubGoal>& subgoals);
    
    // Detect evidence contradictions
    std::vector<std::pair<std::string, std::string>> DetectContradictions(
        const std::vector<Evidence>& evidence);
    
    // ==================== Configuration ====================
    
    void SetConfidenceConfig(const ConfidenceConfig& config);
    ConfidenceConfig GetConfidenceConfig() const;
    
    // ==================== Metrics ====================
    
    struct ReflectionMetrics {
        int total_reflections{0};
        int replans_triggered{0};
        int anomalies_detected{0};
        int patterns_extracted{0};
        float average_confidence_improvement{0.0f};
        std::chrono::milliseconds average_reflection_time{0};
        std::chrono::milliseconds total_reflection_time{0};
        std::unordered_map<std::string, AgentPerformance> agent_performance;
        std::vector<DiscoveredPattern> discovered_patterns;
    };
    ReflectionMetrics GetMetrics() const;
    void ResetMetrics();
    
    // Get reflection history
    std::vector<ReflectionEvent> GetReflectionHistory(size_t count = 100) const;
    
private:
    CognitiveBlackboard* m_blackboard;
    MissionDirector* m_director;
    KnowledgeGraph* m_knowledge_graph;
    DynamicPlanner* m_planner;
    
    std::atomic<bool> m_running{false};
    std::thread m_reflection_thread;
    std::queue<ReflectionEvent> m_event_queue;
    std::mutex m_event_mutex;
    std::condition_variable m_event_cv;
    
    // Configuration
    ConfidenceConfig m_confidence_config;
    
    // State
    std::unordered_map<std::string, AgentPerformance> m_agent_performance;
    std::vector<DiscoveredPattern> m_discovered_patterns;
    std::vector<ReflectionEvent> m_reflection_history;
    mutable std::mutex m_state_mutex;
    
    // Metrics
    ReflectionMetrics m_metrics;
    mutable std::mutex m_metrics_mutex;
    std::chrono::steady_clock::time_point m_last_reflection;
    
    // Main reflection loop
    void ReflectionLoop();
    void ProcessEvent(const ReflectionEvent& event);
    
    // Helper methods
    float BayesianUpdate(float prior, float likelihood);
    float WeightedConfidenceAggregation(const std::vector<float>& confidences,
                                       const std::vector<float>& weights);
    void UpdateMetrics(const std::chrono::steady_clock::time_point& start);
    void PruneOldPatterns(std::chrono::days max_age = std::chrono::days(30));
};

} // namespace rawrxd::agentic
