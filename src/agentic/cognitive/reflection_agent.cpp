/**
 * @file reflection_agent.cpp
 * @brief Implementation of Reflection Agent self-correction loop
 */

#include "reflection_agent.hpp"
#include "mission_director.hpp"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <numeric>

namespace rawrxd::cognitive {

// ============================================================================
// Constructor / Destructor
// ============================================================================

ReflectionAgent::ReflectionAgent(EnhancedBlackboard* blackboard,
                                  class MissionDirector* director,
                                  class DynamicPlanner* planner)
    : m_blackboard(blackboard)
    , m_director(director)
    , m_planner(planner)
    , m_last_reflection(std::chrono::steady_clock::now()) {}

ReflectionAgent::~ReflectionAgent() {
    Stop();
}

// ============================================================================
// Lifecycle
// ============================================================================

void ReflectionAgent::Start() {
    if (m_running.exchange(true)) return; // Already running
    m_reflection_thread = std::thread(&ReflectionAgent::ReflectionLoop, this);
}

void ReflectionAgent::Stop() {
    m_running = false;
    if (m_reflection_thread.joinable()) {
        m_reflection_thread.join();
    }
}

// ============================================================================
// Background Reflection Loop
// ============================================================================

void ReflectionAgent::ReflectionLoop() {
    while (m_running.load()) {
        auto start = std::chrono::steady_clock::now();
        
        // Periodic reflection
        auto result = PeriodicReflection();
        
        auto end = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        
        UpdateMetrics(result, duration);
        
        // Sleep until next reflection interval
        std::this_thread::sleep_for(m_reflection_interval);
    }
}

// ============================================================================
// Explicit Reflection Methods
// ============================================================================

ReflectionResult ReflectionAgent::ReflectOnPhase(const std::string& phase_name,
                                                  const std::unordered_map<std::string, float>& results) {
    auto start = std::chrono::steady_clock::now();
    ReflectionResult result;
    result.confidence_before = 0.0f;
    
    // Gather all hypotheses for this phase
    auto hypotheses = m_blackboard->GetActiveHypotheses();
    
    // Calculate average confidence before reflection
    if (!hypotheses.empty()) {
        float total = 0.0f;
        for (const auto& hyp : hypotheses) {
            total += hyp.confidence;
        }
        result.confidence_before = total / hypotheses.size();
    }
    
    // Analyze results
    bool has_failures = false;
    bool has_low_confidence = false;
    
    for (const auto& [key, value] : results) {
        if (value < m_replan_threshold) {
            has_low_confidence = true;
            result.suggested_actions.push_back("Investigate low confidence in: " + key);
        }
        if (value < 0.1f) {
            has_failures = true;
        }
    }
    
    // Detect anomalies
    auto anomalies = DetectAnomalies(phase_name);
    if (!anomalies.empty()) {
        result.should_replan = true;
        result.reason = "Anomalies detected during phase: " + phase_name;
        for (const auto& anomaly : anomalies) {
            result.suggested_actions.push_back(anomaly.recommended_action);
        }
    }
    
    // Check if confidence is declining
    if (IsConfidenceDeclining(phase_name)) {
        result.should_replan = true;
        result.reason = "Confidence declining in phase: " + phase_name;
        result.suggested_actions.push_back("Switch to alternative analysis approach");
        result.suggested_actions.push_back("Increase sampling depth");
    }
    
    // Calculate confidence after
    if (!hypotheses.empty()) {
        float total = 0.0f;
        for (const auto& hyp : hypotheses) {
            total += hyp.confidence;
        }
        result.confidence_after = total / hypotheses.size();
    }
    
    auto end = std::chrono::steady_clock::now();
    result.reflection_time = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    return result;
}

ReflectionResult ReflectionAgent::ReflectOnAgentResult(const std::string& agent_name,
                                                        const std::string& task_id,
                                                        const std::unordered_map<std::string, float>& results) {
    auto start = std::chrono::steady_clock::now();
    ReflectionResult result;
    
    // Get agent performance
    auto perf = m_blackboard->GetAgentPerformance(agent_name);
    float previous_success_rate = perf ? perf->SuccessRate() : 0.5f;
    
    // Calculate current success rate from results
    float total_score = 0.0f;
    int count = 0;
    for (const auto& [key, value] : results) {
        total_score += value;
        count++;
    }
    float current_score = count > 0 ? total_score / count : 0.0f;
    
    // Update agent weights
    UpdateAgentWeights(agent_name, current_score);
    
    // Determine if agent is underperforming
    if (current_score < m_replan_threshold && previous_success_rate > m_replan_threshold) {
        result.should_replan = true;
        result.reason = "Agent " + agent_name + " performance degraded";
        result.agents_to_retry.push_back(agent_name);
        result.suggested_actions.push_back("Retry with alternative parameters");
        result.suggested_actions.push_back("Switch to backup agent");
    }
    
    // Extract patterns from successful results
    if (current_score > 0.8f) {
        std::vector<Evidence> evidence;
        for (const auto& [key, value] : results) {
            evidence.push_back(Evidence(key, agent_name, value));
        }
        ExtractPatterns(evidence);
    }
    
    auto end = std::chrono::steady_clock::now();
    result.reflection_time = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    return result;
}

ReflectionResult ReflectionAgent::ReflectOnHypothesis(const std::string& hypothesis_id) {
    auto start = std::chrono::steady_clock::now();
    ReflectionResult result;
    
    auto hypothesis_opt = m_blackboard->GetHypothesis(hypothesis_id);
    if (!hypothesis_opt) return result;
    
    const auto& hypothesis = *hypothesis_opt;
    result.confidence_before = hypothesis.confidence;
    
    // Get all evidence for this hypothesis
    auto evidence = m_blackboard->GetEvidenceForHypothesis(hypothesis_id);
    
    // Recalculate confidence
    Confidence new_confidence = ScoreHypothesis(hypothesis);
    m_blackboard->UpdateHypothesisConfidence(hypothesis_id, new_confidence);
    result.confidence_after = new_confidence;
    
    // Check if confidence dropped significantly
    if (new_confidence < hypothesis.confidence - 0.2f) {
        result.should_replan = true;
        result.reason = "Hypothesis confidence dropped significantly";
        result.suggested_actions.push_back("Re-evaluate supporting evidence");
        result.suggested_actions.push_back("Seek contradictory evidence");
        result.suggested_actions.push_back("Consider alternative hypotheses");
    }
    
    // Check if hypothesis is confirmed
    if (new_confidence > 0.9f && hypothesis.status == Hypothesis::Status::UNDER_TEST) {
        m_blackboard->UpdateHypothesisStatus(hypothesis_id, Hypothesis::Status::CONFIRMED);
        result.suggested_actions.push_back("Hypothesis confirmed: " + hypothesis.claim);
    }
    
    // Check if hypothesis should be refuted
    if (new_confidence < 0.1f && hypothesis.status != Hypothesis::Status::REFUTED) {
        m_blackboard->UpdateHypothesisStatus(hypothesis_id, Hypothesis::Status::REFUTED);
        result.should_replan = true;
        result.reason = "Hypothesis refuted: " + hypothesis.claim;
        result.new_hypotheses.push_back("Alternative to: " + hypothesis.claim);
    }
    
    auto end = std::chrono::steady_clock::now();
    result.reflection_time = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    return result;
}

ReflectionResult ReflectionAgent::PeriodicReflection() {
    auto start = std::chrono::steady_clock::now();
    ReflectionResult result;
    
    // Get current cognitive state
    auto state = m_blackboard->GetCognitiveState();
    
    // Analyze all active hypotheses
    for (const auto& hyp : state.active_hypotheses) {
        auto hyp_result = ReflectOnHypothesis(hyp.id);
        if (hyp_result.should_replan) {
            result.should_replan = true;
            result.reason += hyp_result.reason + "; ";
        }
        result.suggested_actions.insert(result.suggested_actions.end(),
                                         hyp_result.suggested_actions.begin(),
                                         hyp_result.suggested_actions.end());
    }
    
    // Check for stalled tasks
    auto active_tasks = state.active_tasks;
    auto now = std::chrono::system_clock::now();
    for (const auto& task : active_tasks) {
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            now - task.started_time).count();
        if (elapsed > task.subgoal.timeout.count()) {
            result.should_replan = true;
            result.reason += "Task timeout: " + task.id + "; ";
            result.suggested_actions.push_back("Cancel timed-out task: " + task.id);
            result.suggested_actions.push_back("Retry with extended timeout");
        }
    }
    
    // Check overall mission confidence
    if (!state.active_hypotheses.empty()) {
        float avg_confidence = 0.0f;
        for (const auto& hyp : state.active_hypotheses) {
            avg_confidence += hyp.confidence;
        }
        avg_confidence /= state.active_hypotheses.size();
        
        if (avg_confidence < m_replan_threshold) {
            result.should_replan = true;
            result.reason += "Overall mission confidence too low; ";
            result.suggested_actions.push_back("Broaden analysis scope");
            result.suggested_actions.push_back("Request additional resources");
        }
    }
    
    // Detect anomalies across all missions
    auto missions = m_blackboard->GetAllMissionMetrics();
    for (const auto& mission : missions) {
        auto anomalies = DetectAnomalies(mission.mission_id);
        for (const auto& anomaly : anomalies) {
            if (anomaly.severity > 0.7f) {
                result.should_replan = true;
                result.reason += "Severe anomaly: " + anomaly.description + "; ";
            }
        }
    }
    
    auto end = std::chrono::steady_clock::now();
    result.reflection_time = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    return result;
}

// ============================================================================
// Confidence Scoring
// ============================================================================

Confidence ReflectionAgent::ScoreHypothesis(const Hypothesis& hypothesis) const {
    auto evidence = m_blackboard->GetEvidenceForHypothesis(hypothesis.id);
    
    if (evidence.empty()) return hypothesis.confidence;
    
    float supporting = 0.0f;
    float supporting_weight = 0.0f;
    float contradicting = 0.0f;
    float contradicting_weight = 0.0f;
    
    for (const auto& ev : evidence) {
        float w = std::abs(ev.weight);
        if (ev.weight > 0) {
            supporting += ev.confidence * w;
            supporting_weight += w;
        } else {
            contradicting += ev.confidence * w;
            contradicting_weight += w;
        }
    }
    
    if (supporting_weight + contradicting_weight == 0.0f) {
        return hypothesis.confidence;
    }
    
    // Bayesian-inspired scoring
    float prior = hypothesis.confidence;
    float likelihood = supporting_weight > 0 ? supporting / supporting_weight : 0.0f;
    float contradiction = contradicting_weight > 0 ? contradicting / contradicting_weight : 0.0f;
    
    float posterior = (prior * likelihood) / 
        (prior * likelihood + (1.0f - prior) * std::max(contradiction, 0.01f));
    
    return std::clamp(posterior, 0.0f, 1.0f);
}

Confidence ReflectionAgent::ScoreMission(const std::string& mission_id) const {
    auto hypotheses = m_blackboard->GetHypothesesByMission(mission_id);
    
    if (hypotheses.empty()) return 0.0f;
    
    float total = 0.0f;
    for (const auto& hyp : hypotheses) {
        total += hyp.confidence;
    }
    
    return total / hypotheses.size();
}

Confidence ReflectionAgent::ScoreAgentPerformance(const std::string& agent_name) const {
    auto perf = m_blackboard->GetAgentPerformance(agent_name);
    if (!perf) return 0.5f;
    
    // Weighted combination of success rate and average confidence
    float success_rate = perf->SuccessRate();
    float avg_confidence = perf->average_confidence;
    
    return (success_rate * 0.6f) + (avg_confidence * 0.4f);
}

Confidence ReflectionAgent::CalculateWeightedConfidence(
    const std::vector<std::pair<Confidence, float>>& factors) const {
    
    float total_weight = 0.0f;
    float weighted_sum = 0.0f;
    
    for (const auto& [confidence, weight] : factors) {
        total_weight += weight;
        weighted_sum += confidence * weight;
    }
    
    if (total_weight == 0.0f) return 0.0f;
    return std::clamp(weighted_sum / total_weight, 0.0f, 1.0f);
}

// ============================================================================
// Anomaly Detection
// ============================================================================

std::vector<ReflectionAgent::Anomaly> ReflectionAgent::DetectAnomalies(const std::string& mission_id) const {
    std::vector<Anomaly> anomalies;
    
    // Check for failed tasks
    auto failed_tasks = m_blackboard->GetFailedTasks();
    if (failed_tasks.size() > 3) {
        Anomaly anomaly;
        anomaly.description = "Multiple task failures detected";
        anomaly.affected_component = mission_id;
        anomaly.severity = std::min(0.3f + (failed_tasks.size() * 0.1f), 1.0f);
        anomaly.recommended_action = "Review agent capabilities and retry with alternatives";
        anomalies.push_back(anomaly);
    }
    
    // Check for declining confidence trend
    if (IsConfidenceDeclining(mission_id)) {
        Anomaly anomaly;
        anomaly.description = "Confidence declining over time";
        anomaly.affected_component = mission_id;
        anomaly.severity = 0.6f;
        anomaly.recommended_action = "Re-evaluate approach and consider alternative hypotheses";
        anomalies.push_back(anomaly);
    }
    
    // Check for stalled tasks
    auto active_tasks = m_blackboard->GetActiveTasks();
    auto now = std::chrono::system_clock::now();
    int stalled_count = 0;
    for (const auto& task : active_tasks) {
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - task.started_time).count();
        if (elapsed > task.subgoal.timeout.count() * 2) {
            stalled_count++;
        }
    }
    if (stalled_count > 0) {
        Anomaly anomaly;
        anomaly.description = std::to_string(stalled_count) + " tasks appear stalled";
        anomaly.affected_component = mission_id;
        anomaly.severity = std::min(0.4f + (stalled_count * 0.15f), 1.0f);
        anomaly.recommended_action = "Cancel stalled tasks and reassign";
        anomalies.push_back(anomaly);
    }
    
    // Check for conflicting evidence
    auto hypotheses = m_blackboard->GetHypothesesByMission(mission_id);
    for (const auto& hyp : hypotheses) {
        if (!hyp.supporting_evidence.empty() && !hyp.contradicting_evidence.empty()) {
            float support_conf = 0.0f;
            float contra_conf = 0.0f;
            
            for (const auto& ev_id : hyp.supporting_evidence) {
                auto ev = m_blackboard->GetEvidence(ev_id);
                if (ev) support_conf += ev->confidence;
            }
            for (const auto& ev_id : hyp.contradicting_evidence) {
                auto ev = m_blackboard->GetEvidence(ev_id);
                if (ev) contra_conf += ev->confidence;
            }
            
            if (contra_conf > support_conf * 0.5f) {
                Anomaly anomaly;
                anomaly.description = "Significant conflicting evidence for hypothesis: " + hyp.claim;
                anomaly.affected_component = hyp.id;
                anomaly.severity = 0.7f;
                anomaly.recommended_action = "Prioritize resolution of conflicting evidence";
                anomalies.push_back(anomaly);
            }
        }
    }
    
    return anomalies;
}

bool ReflectionAgent::IsAnomaly(const Evidence& evidence, const Hypothesis& hypothesis) const {
    // Evidence is anomalous if it strongly contradicts a high-confidence hypothesis
    if (evidence.weight < 0 && hypothesis.confidence > 0.8f) {
        return evidence.confidence > 0.7f; // Strong contradiction of strong hypothesis
    }
    return false;
}

// ============================================================================
// Replanning Triggers
// ============================================================================

bool ReflectionAgent::ShouldReplan(const std::string& mission_id) const {
    auto metrics = m_blackboard->GetMissionMetrics(mission_id);
    if (!metrics) return false;
    
    // Trigger replan if too many failures
    if (metrics->failed_subgoals > metrics->completed_subgoals / 2) {
        return true;
    }
    
    // Trigger replan if confidence too low
    if (ScoreMission(mission_id) < m_replan_threshold) {
        return true;
    }
    
    // Trigger replan if anomalies detected
    auto anomalies = DetectAnomalies(mission_id);
    for (const auto& anomaly : anomalies) {
        if (anomaly.severity > 0.8f) return true;
    }
    
    return false;
}

bool ReflectionAgent::ShouldReplan(const std::vector<SubGoal>& current_plan,
                                    const std::vector<Hypothesis>& hypotheses) const {
    // Count failures
    int failures = 0;
    for (const auto& sg : current_plan) {
        if (sg.status == SubGoal::Status::FAILED) failures++;
    }
    
    if (failures > static_cast<int>(current_plan.size()) / 3) {
        return true;
    }
    
    // Check hypothesis confidence
    float avg_confidence = 0.0f;
    for (const auto& hyp : hypotheses) {
        avg_confidence += hyp.confidence;
    }
    if (!hypotheses.empty()) {
        avg_confidence /= hypotheses.size();
        if (avg_confidence < m_replan_threshold) return true;
    }
    
    return false;
}

std::vector<std::string> ReflectionAgent::IdentifyFailedStrategies(const std::string& mission_id) const {
    std::vector<std::string> failed;
    
    auto tasks = m_blackboard->GetFailedTasks();
    for (const auto& task : tasks) {
        if (task.subgoal.parent_mission == mission_id) {
            for (const auto& cap : task.subgoal.required_capabilities) {
                if (std::find(failed.begin(), failed.end(), cap) == failed.end()) {
                    failed.push_back(cap);
                }
            }
        }
    }
    
    return failed;
}

// ============================================================================
// Learning & Pattern Extraction
// ============================================================================

void ReflectionAgent::ExtractPatterns(const std::vector<Evidence>& evidence) {
    std::lock_guard<std::mutex> lock(m_metrics_mutex);
    
    for (const auto& ev : evidence) {
        // Simple pattern extraction based on evidence source and description
        std::string pattern_type = ev.source_agent + ":" + ev.description.substr(0, 20);
        
        auto it = m_extracted_patterns.find(pattern_type);
        if (it == m_extracted_patterns.end()) {
            m_extracted_patterns[pattern_type] = {ev.description};
            m_metrics.patterns_extracted++;
        } else {
            it->second.push_back(ev.description);
        }
    }
}

void ReflectionAgent::UpdateAgentWeights(const std::string& agent_name, float success_rate) {
    std::lock_guard<std::mutex> lock(m_metrics_mutex);
    
    // Exponential moving average
    float alpha = 0.3f; // Learning rate
    auto it = m_agent_weights.find(agent_name);
    if (it == m_agent_weights.end()) {
        m_agent_weights[agent_name] = success_rate;
    } else {
        it->second = (alpha * success_rate) + ((1.0f - alpha) * it->second);
    }
    
    m_agent_performance_history[agent_name].push_back(success_rate);
    
    // Keep only last 100 entries
    if (m_agent_performance_history[agent_name].size() > 100) {
        m_agent_performance_history[agent_name].erase(
            m_agent_performance_history[agent_name].begin());
    }
}

void ReflectionAgent::RecordPattern(const std::string& pattern_type,
                                     const std::string& description,
                                     float success_rate) {
    std::lock_guard<std::mutex> lock(m_metrics_mutex);
    
    auto it = m_extracted_patterns.find(pattern_type);
    if (it == m_extracted_patterns.end()) {
        m_extracted_patterns[pattern_type] = {description};
    } else {
        it->second.push_back(description);
    }
}

// ============================================================================
// Performance Metrics
// ============================================================================

ReflectionAgent::Metrics ReflectionAgent::GetMetrics() const {
    std::lock_guard<std::mutex> lock(m_metrics_mutex);
    return m_metrics;
}

void ReflectionAgent::ResetMetrics() {
    std::lock_guard<std::mutex> lock(m_metrics_mutex);
    m_metrics = Metrics{};
}

// ============================================================================
// Utility
// ============================================================================

std::string ReflectionAgent::GenerateReflectionReport(const std::string& mission_id) const {
    std::ostringstream oss;
    
    auto metrics = GetMetrics();
    auto mission_opt = m_blackboard->GetMissionMetrics(mission_id);
    
    oss << "=== Reflection Report ===\n";
    oss << "Mission: " << mission_id << "\n";
    oss << "Total Reflections: " << metrics.total_reflections << "\n";
    oss << "Replans Triggered: " << metrics.replans_triggered << "\n";
    oss << "Anomalies Detected: " << metrics.anomalies_detected << "\n";
    oss << "Patterns Extracted: " << metrics.patterns_extracted << "\n";
    
    if (mission_opt) {
        oss << "Mission Progress: " << mission_opt->CompletionPercentage() << "%\n";
        oss << "Final Confidence: " << mission_opt->final_confidence << "\n";
    }
    
    oss << "\nAgent Performance:\n";
    for (const auto& [agent, rate] : metrics.agent_success_rates) {
        oss << "  " << agent << ": " << std::fixed << std::setprecision(2) << rate << "%\n";
    }
    
    return oss.str();
}

std::vector<std::string> ReflectionAgent::GetRecommendations(const std::string& mission_id) const {
    std::vector<std::string> recommendations;
    
    // Analyze failed strategies
    auto failed = IdentifyFailedStrategies(mission_id);
    if (!failed.empty()) {
        recommendations.push_back("Avoid strategies: " + 
            std::accumulate(failed.begin(), failed.end(), std::string(),
                [](const std::string& a, const std::string& b) {
                    return a.empty() ? b : a + ", " + b;
                }));
    }
    
    // Check agent performance
    auto agents = m_blackboard->GetAllAgentPerformance();
    for (const auto& perf : agents) {
        if (perf.SuccessRate() < 0.3f) {
            recommendations.push_back("Consider replacing agent: " + perf.agent_name);
        } else if (perf.SuccessRate() > 0.9f) {
            recommendations.push_back("Agent performing well: " + perf.agent_name);
        }
    }
    
    // Check for underexplored hypotheses
    auto hypotheses = m_blackboard->GetHypothesesByMission(mission_id);
    for (const auto& hyp : hypotheses) {
        if (hyp.status == Hypothesis::Status::UNVERIFIED && hyp.confidence > 0.5f) {
            recommendations.push_back("Prioritize verification of: " + hyp.claim);
        }
    }
    
    return recommendations;
}

// ============================================================================
// Internal Helpers
// ============================================================================

ReflectionResult ReflectionAgent::AnalyzeEvidence(const std::vector<Evidence>& evidence,
                                                    const std::vector<Hypothesis>& hypotheses) {
    ReflectionResult result;
    
    // Group evidence by hypothesis
    std::unordered_map<std::string, std::vector<Evidence>> evidence_by_hypothesis;
    for (const auto& ev : evidence) {
        evidence_by_hypothesis[ev.target_hypothesis].push_back(ev);
    }
    
    // Analyze each hypothesis
    for (const auto& hyp : hypotheses) {
        auto it = evidence_by_hypothesis.find(hyp.id);
        if (it == evidence_by_hypothesis.end()) continue;
        
        float support = 0.0f;
        float contra = 0.0f;
        
        for (const auto& ev : it->second) {
            if (ev.weight > 0) support += ev.confidence;
            else contra += ev.confidence;
        }
        
        if (contra > support * 0.8f) {
            result.should_replan = true;
            result.reason += "Conflicting evidence for " + hyp.claim + "; ";
        }
    }
    
    return result;
}

std::vector<std::string> ReflectionAgent::SuggestNewActions(const Hypothesis& hypothesis) const {
    std::vector<std::string> actions;
    
    if (hypothesis.confidence < 0.3f) {
        actions.push_back("Gather more supporting evidence");
        actions.push_back("Seek alternative explanations");
    } else if (hypothesis.confidence > 0.7f) {
        actions.push_back("Verify with independent method");
        actions.push_back("Document findings");
    }
    
    if (hypothesis.status == Hypothesis::Status::REFUTED) {
        actions.push_back("Formulate new hypothesis");
        actions.push_back("Review evidence quality");
    }
    
    return actions;
}

std::vector<std::string> ReflectionAgent::SuggestAlternativeAgents(const SubGoal& failed_subgoal) const {
    std::vector<std::string> alternatives;
    
    for (const auto& cap : failed_subgoal.required_capabilities) {
        auto agents = m_blackboard->FindAgentsWithCapability(cap);
        for (const auto& agent : agents) {
            if (agent != failed_subgoal.assigned_agent) {
                alternatives.push_back(agent);
            }
        }
    }
    
    // Remove duplicates
    std::sort(alternatives.begin(), alternatives.end());
    alternatives.erase(std::unique(alternatives.begin(), alternatives.end()), alternatives.end());
    
    return alternatives;
}

float ReflectionAgent::CalculateTrend(const std::vector<float>& values) const {
    if (values.size() < 2) return 0.0f;
    
    // Simple linear regression slope
    float n = static_cast<float>(values.size());
    float sum_x = 0.0f, sum_y = 0.0f, sum_xy = 0.0f, sum_x2 = 0.0f;
    
    for (size_t i = 0; i < values.size(); ++i) {
        float x = static_cast<float>(i);
        float y = values[i];
        sum_x += x;
        sum_y += y;
        sum_xy += x * y;
        sum_x2 += x * x;
    }
    
    float denominator = n * sum_x2 - sum_x * sum_x;
    if (std::abs(denominator) < 0.0001f) return 0.0f;
    
    return (n * sum_xy - sum_x * sum_y) / denominator;
}

bool ReflectionAgent::IsConfidenceDeclining(const std::string& mission_id) const {
    auto it = m_agent_performance_history.find(mission_id);
    if (it == m_agent_performance_history.end() || it->second.size() < 3) {
        return false;
    }
    
    float trend = CalculateTrend(it->second);
    return trend < -0.05f; // Declining trend
}

void ReflectionAgent::UpdateMetrics(const ReflectionResult& result, 
                                       std::chrono::milliseconds duration) {
    std::lock_guard<std::mutex> lock(m_metrics_mutex);
    
    m_metrics.total_reflections++;
    
    if (result.should_replan) {
        m_metrics.replans_triggered++;
        m_metrics.replan_reasons[result.reason]++;
    }
    
    // Update average reflection time
    m_metrics.average_reflection_time = 
        (m_metrics.average_reflection_time * (m_metrics.total_reflections - 1) + duration) 
        / m_metrics.total_reflections;
    
    // Update confidence improvement
    float improvement = result.confidence_after - result.confidence_before;
    m_metrics.average_confidence_improvement = 
        (m_metrics.average_confidence_improvement * (m_metrics.total_reflections - 1) + improvement)
        / m_metrics.total_reflections;
}

} // namespace rawrxd::cognitive
