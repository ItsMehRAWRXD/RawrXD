/**
 * @file reflection_agent.hpp
 * @brief Self-correction and learning agent for autonomous RE
 * @description The Reflection Agent continuously evaluates mission progress,
 *              scores confidence, detects anomalies, and triggers replanning.
 *              It maintains performance metrics for all agents and learns
 *              from successes and failures.
 * @version 1.0.0
 * @date 2026-07-22
 */

#pragma once

#include "cognitive_types.hpp"
#include "enhanced_blackboard.hpp"
#include <atomic>
#include <thread>
#include <queue>

namespace rawrxd::cognitive {

// ============================================================================
// Reflection Event Types
// ============================================================================

enum class ReflectionTrigger {
    PHASE_COMPLETE,      // A major phase finished
    AGENT_RESULT,        // An agent produced results
    CONFIDENCE_DROP,     // Confidence fell below threshold
    ANOMALY_DETECTED,    // Unexpected behavior observed
    TIMEOUT,             // Task exceeded time limit
    USER_FEEDBACK,       // Human provided feedback
    PERIODIC             // Scheduled periodic reflection
};

// ============================================================================
// Reflection Result
// ============================================================================

struct ReflectionResult {
    bool should_replan{false};
    std::string reason;
    std::vector<std::string> suggested_actions;
    std::vector<std::string> agents_to_retry;
    std::vector<std::string> new_hypotheses;
    float confidence_before{0.0f};
    float confidence_after{0.0f};
    std::chrono::milliseconds reflection_time{0};
};

// ============================================================================
// Reflection Agent
// ============================================================================

class ReflectionAgent {
public:
    ReflectionAgent(EnhancedBlackboard* blackboard,
                    class MissionDirector* director,
                    class DynamicPlanner* planner);
    ~ReflectionAgent();
    
    // Prevent copy/move
    ReflectionAgent(const ReflectionAgent&) = delete;
    ReflectionAgent& operator=(const ReflectionAgent&) = delete;
    ReflectionAgent(ReflectionAgent&&) = delete;
    ReflectionAgent& operator=(ReflectionAgent&&) = delete;
    
    // ------------------------------------------------------------------------
    // Lifecycle
    // ------------------------------------------------------------------------
    void Start();
    void Stop();
    bool IsRunning() const { return m_running.load(); }
    
    // ------------------------------------------------------------------------
    // Explicit Reflection (triggered by external events)
    // ------------------------------------------------------------------------
    ReflectionResult ReflectOnPhase(const std::string& phase_name,
                                     const std::unordered_map<std::string, float>& results);
    ReflectionResult ReflectOnAgentResult(const std::string& agent_name,
                                          const std::string& task_id,
                                          const std::unordered_map<std::string, float>& results);
    ReflectionResult ReflectOnHypothesis(const std::string& hypothesis_id);
    ReflectionResult PeriodicReflection();
    
    // ------------------------------------------------------------------------
    // Confidence Scoring
    // ------------------------------------------------------------------------
    Confidence ScoreHypothesis(const Hypothesis& hypothesis) const;
    Confidence ScoreMission(const std::string& mission_id) const;
    Confidence ScoreAgentPerformance(const std::string& agent_name) const;
    
    // Weighted confidence combining multiple factors
    Confidence CalculateWeightedConfidence(const std::vector<std::pair<Confidence, float>>& factors) const;
    
    // ------------------------------------------------------------------------
    // Anomaly Detection
    // ------------------------------------------------------------------------
    struct Anomaly {
        std::string description;
        std::string affected_component;
        float severity{0.0f}; // 0.0 - 1.0
        std::string recommended_action;
    };
    
    std::vector<Anomaly> DetectAnomalies(const std::string& mission_id) const;
    bool IsAnomaly(const Evidence& evidence, const Hypothesis& hypothesis) const;
    
    // ------------------------------------------------------------------------
    // Replanning Triggers
    // ------------------------------------------------------------------------
    bool ShouldReplan(const std::string& mission_id) const;
    bool ShouldReplan(const std::vector<SubGoal>& current_plan,
                      const std::vector<Hypothesis>& hypotheses) const;
    std::vector<std::string> IdentifyFailedStrategies(const std::string& mission_id) const;
    
    // ------------------------------------------------------------------------
    // Learning & Pattern Extraction
    // ------------------------------------------------------------------------
    void ExtractPatterns(const std::vector<Evidence>& evidence);
    void UpdateAgentWeights(const std::string& agent_name, float success_rate);
    void RecordPattern(const std::string& pattern_type,
                       const std::string& description,
                       float success_rate);
    
    // ------------------------------------------------------------------------
    // Performance Metrics
    // ------------------------------------------------------------------------
    struct Metrics {
        int total_reflections{0};
        int replans_triggered{0};
        int anomalies_detected{0};
        int patterns_extracted{0};
        float average_confidence_improvement{0.0f};
        std::chrono::milliseconds average_reflection_time{0};
        std::unordered_map<std::string, float> agent_success_rates;
        std::unordered_map<std::string, int> replan_reasons;
    };
    
    Metrics GetMetrics() const;
    void ResetMetrics();
    
    // ------------------------------------------------------------------------
    // Utility
    // ------------------------------------------------------------------------
    std::string GenerateReflectionReport(const std::string& mission_id) const;
    std::vector<std::string> GetRecommendations(const std::string& mission_id) const;
    
private:
    EnhancedBlackboard* m_blackboard;
    class MissionDirector* m_director;
    class DynamicPlanner* m_planner;
    
    std::atomic<bool> m_running{false};
    std::thread m_reflection_thread;
    mutable std::mutex m_metrics_mutex;
    Metrics m_metrics;
    
    // Internal state
    std::unordered_map<std::string, float> m_agent_weights;
    std::unordered_map<std::string, std::vector<float>> m_agent_performance_history;
    std::unordered_map<std::string, std::vector<std::string>> m_extracted_patterns;
    std::chrono::steady_clock::time_point m_last_reflection;
    
    // Configuration
    Confidence m_replan_threshold{0.3f};      // Trigger replan if confidence drops below this
    Confidence m_anomaly_threshold{0.2f};   // Flag anomalies below this confidence
    std::chrono::seconds m_reflection_interval{30}; // Periodic reflection every 30s
    
    // Background reflection loop
    void ReflectionLoop();
    
    // Helper methods
    ReflectionResult AnalyzeEvidence(const std::vector<Evidence>& evidence,
                                      const std::vector<Hypothesis>& hypotheses);
    std::vector<std::string> SuggestNewActions(const Hypothesis& hypothesis) const;
    std::vector<std::string> SuggestAlternativeAgents(const SubGoal& failed_subgoal) const;
    float CalculateTrend(const std::vector<float>& values) const;
    bool IsConfidenceDeclining(const std::string& mission_id) const;
    void UpdateMetrics(const ReflectionResult& result, std::chrono::milliseconds duration);
};

} // namespace rawrxd::cognitive
