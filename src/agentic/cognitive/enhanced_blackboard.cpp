/**
 * @file enhanced_blackboard.cpp
 * @brief Implementation of EnhancedBlackboard working memory
 */

#include "enhanced_blackboard.hpp"
#include <algorithm>
#include <sstream>
#include <iomanip>

namespace rawrxd::cognitive {

EnhancedBlackboard::EnhancedBlackboard() 
    : m_last_update(std::chrono::system_clock::now()) {}

EnhancedBlackboard::~EnhancedBlackboard() = default;

// ============================================================================
// Evidence Management
// ============================================================================

std::string EnhancedBlackboard::AddEvidence(Evidence&& evidence) {
    std::unique_lock lock(m_mutex);
    
    if (evidence.id.empty()) {
        evidence.id = GenerateUUID();
    }
    
    std::string id = evidence.id;
    m_evidence[id] = std::move(evidence);
    
    lock.unlock();
    EmitEvent(BlackboardEvent::EVIDENCE_ADDED, id);
    return id;
}

void EnhancedBlackboard::UpdateEvidenceConfidence(const std::string& id, Confidence new_confidence) {
    std::unique_lock lock(m_mutex);
    auto it = m_evidence.find(id);
    if (it != m_evidence.end()) {
        it->second.confidence = std::clamp(new_confidence, 0.0f, 1.0f);
        it->second.timestamp = std::chrono::system_clock::now();
        
        // Update any hypotheses that use this evidence
        for (auto& [hyp_id, hyp] : m_hypotheses) {
            if (std::find(hyp.supporting_evidence.begin(), hyp.supporting_evidence.end(), id) != hyp.supporting_evidence.end() ||
                std::find(hyp.contradicting_evidence.begin(), hyp.contradicting_evidence.end(), id) != hyp.contradicting_evidence.end()) {
                RecalculateHypothesisConfidence(hyp_id);
            }
        }
    }
    lock.unlock();
    EmitEvent(BlackboardEvent::EVIDENCE_UPDATED, id);
}

void EnhancedBlackboard::UpdateEvidenceWeight(const std::string& id, float new_weight) {
    std::unique_lock lock(m_mutex);
    auto it = m_evidence.find(id);
    if (it != m_evidence.end()) {
        it->second.weight = new_weight;
        it->second.timestamp = std::chrono::system_clock::now();
    }
}

std::optional<Evidence> EnhancedBlackboard::GetEvidence(const std::string& id) const {
    std::shared_lock lock(m_mutex);
    auto it = m_evidence.find(id);
    if (it != m_evidence.end()) return it->second;
    return std::nullopt;
}

std::vector<Evidence> EnhancedBlackboard::GetEvidenceForHypothesis(const std::string& hypothesis_id) const {
    std::shared_lock lock(m_mutex);
    std::vector<Evidence> result;
    
    auto hyp_it = m_hypotheses.find(hypothesis_id);
    if (hyp_it == m_hypotheses.end()) return result;
    
    for (const auto& ev_id : hyp_it->second.supporting_evidence) {
        auto ev_it = m_evidence.find(ev_id);
        if (ev_it != m_evidence.end()) result.push_back(ev_it->second);
    }
    for (const auto& ev_id : hyp_it->second.contradicting_evidence) {
        auto ev_it = m_evidence.find(ev_id);
        if (ev_it != m_evidence.end()) result.push_back(ev_it->second);
    }
    
    return result;
}

std::vector<Evidence> EnhancedBlackboard::GetEvidenceByAgent(const std::string& agent_name) const {
    std::shared_lock lock(m_mutex);
    std::vector<Evidence> result;
    for (const auto& [id, ev] : m_evidence) {
        if (ev.source_agent == agent_name) result.push_back(ev);
    }
    return result;
}

std::vector<Evidence> EnhancedBlackboard::GetRecentEvidence(size_t count) const {
    std::shared_lock lock(m_mutex);
    std::vector<Evidence> result;
    for (const auto& [id, ev] : m_evidence) {
        result.push_back(ev);
    }
    
    std::sort(result.begin(), result.end(), 
        [](const Evidence& a, const Evidence& b) {
            return a.timestamp > b.timestamp;
        });
    
    if (result.size() > count) result.resize(count);
    return result;
}

std::unordered_map<std::string, Confidence> EnhancedBlackboard::GetConfidenceMap() const {
    std::shared_lock lock(m_mutex);
    std::unordered_map<std::string, Confidence> result;
    for (const auto& [id, ev] : m_evidence) {
        result[id] = ev.confidence;
    }
    return result;
}

size_t EnhancedBlackboard::EvidenceCount() const {
    std::shared_lock lock(m_mutex);
    return m_evidence.size();
}

void EnhancedBlackboard::RemoveEvidence(const std::string& id) {
    std::unique_lock lock(m_mutex);
    m_evidence.erase(id);
}

void EnhancedBlackboard::ClearEvidence() {
    std::unique_lock lock(m_mutex);
    m_evidence.clear();
}

// ============================================================================
// Hypothesis Management
// ============================================================================

std::string EnhancedBlackboard::CreateHypothesis(const std::string& claim,
                                                   const std::string& domain,
                                                   const std::string& mission_id,
                                                   int priority) {
    std::unique_lock lock(m_mutex);
    
    Hypothesis hyp(claim, domain, priority);
    hyp.id = GenerateUUID();
    hyp.parent_mission = mission_id;
    hyp.created = std::chrono::system_clock::now();
    hyp.last_updated = hyp.created;
    
    std::string id = hyp.id;
    m_hypotheses[id] = std::move(hyp);
    
    lock.unlock();
    EmitEvent(BlackboardEvent::HYPOTHESIS_CREATED, id);
    return id;
}

void EnhancedBlackboard::UpdateHypothesisConfidence(const std::string& id, Confidence confidence) {
    std::unique_lock lock(m_mutex);
    auto it = m_hypotheses.find(id);
    if (it != m_hypotheses.end()) {
        it->second.confidence = std::clamp(confidence, 0.0f, 1.0f);
        it->second.last_updated = std::chrono::system_clock::now();
    }
}

void EnhancedBlackboard::AddEvidenceToHypothesis(const std::string& hypothesis_id,
                                                  const std::string& evidence_id,
                                                  bool supporting) {
    std::unique_lock lock(m_mutex);
    auto hyp_it = m_hypotheses.find(hypothesis_id);
    if (hyp_it == m_hypotheses.end()) return;
    
    if (supporting) {
        hyp_it->second.supporting_evidence.push_back(evidence_id);
    } else {
        hyp_it->second.contradicting_evidence.push_back(evidence_id);
    }
    
    RecalculateHypothesisConfidence(hypothesis_id);
    ResolveConflicts(hypothesis_id);
}

void EnhancedBlackboard::UpdateHypothesisStatus(const std::string& id, Hypothesis::Status status) {
    std::unique_lock lock(m_mutex);
    auto it = m_hypotheses.find(id);
    if (it != m_hypotheses.end()) {
        it->second.status = status;
        it->second.last_updated = std::chrono::system_clock::now();
    }
    
    BlackboardEvent event = BlackboardEvent::HYPOTHESIS_UPDATED;
    if (status == Hypothesis::Status::CONFIRMED) event = BlackboardEvent::HYPOTHESIS_CONFIRMED;
    if (status == Hypothesis::Status::REFUTED) event = BlackboardEvent::HYPOTHESIS_REFUTED;
    
    lock.unlock();
    EmitEvent(event, id);
}

void EnhancedBlackboard::ProposeAction(const std::string& hypothesis_id, const std::string& action) {
    std::unique_lock lock(m_mutex);
    auto it = m_hypotheses.find(hypothesis_id);
    if (it != m_hypotheses.end()) {
        it->second.proposed_next_action = action;
        it->second.last_updated = std::chrono::system_clock::now();
    }
}

std::optional<Hypothesis> EnhancedBlackboard::GetHypothesis(const std::string& id) const {
    std::shared_lock lock(m_mutex);
    auto it = m_hypotheses.find(id);
    if (it != m_hypotheses.end()) return it->second;
    return std::nullopt;
}

std::vector<Hypothesis> EnhancedBlackboard::GetActiveHypotheses() const {
    std::shared_lock lock(m_mutex);
    std::vector<Hypothesis> result;
    for (const auto& [id, hyp] : m_hypotheses) {
        if (hyp.status != Hypothesis::Status::REFUTED && 
            hyp.status != Hypothesis::Status::DEPRECATED) {
            result.push_back(hyp);
        }
    }
    return result;
}

std::vector<Hypothesis> EnhancedBlackboard::GetHypothesesByDomain(const std::string& domain) const {
    std::shared_lock lock(m_mutex);
    std::vector<Hypothesis> result;
    for (const auto& [id, hyp] : m_hypotheses) {
        if (hyp.domain == domain) result.push_back(hyp);
    }
    return result;
}

std::vector<Hypothesis> EnhancedBlackboard::GetHypothesesByMission(const std::string& mission_id) const {
    std::shared_lock lock(m_mutex);
    std::vector<Hypothesis> result;
    for (const auto& [id, hyp] : m_hypotheses) {
        if (hyp.parent_mission == mission_id) result.push_back(hyp);
    }
    return result;
}

std::optional<Hypothesis> EnhancedBlackboard::GetMostConfidentHypothesis() const {
    std::shared_lock lock(m_mutex);
    std::optional<Hypothesis> best;
    for (const auto& [id, hyp] : m_hypotheses) {
        if (!best || hyp.confidence > best->confidence) {
            best = hyp;
        }
    }
    return best;
}

std::optional<Hypothesis> EnhancedBlackboard::GetHighestPriorityHypothesis() const {
    std::shared_lock lock(m_mutex);
    std::optional<Hypothesis> best;
    for (const auto& [id, hyp] : m_hypotheses) {
        if (!best || hyp.priority > best->priority) {
            best = hyp;
        }
    }
    return best;
}

size_t EnhancedBlackboard::HypothesisCount() const {
    std::shared_lock lock(m_mutex);
    return m_hypotheses.size();
}

void EnhancedBlackboard::RemoveHypothesis(const std::string& id) {
    std::unique_lock lock(m_mutex);
    m_hypotheses.erase(id);
}

void EnhancedBlackboard::ClearHypotheses() {
    std::unique_lock lock(m_mutex);
    m_hypotheses.clear();
}

// ============================================================================
// Task Management
// ============================================================================

void EnhancedBlackboard::ScheduleTask(Task&& task) {
    std::unique_lock lock(m_mutex);
    if (task.id.empty()) task.id = GenerateUUID();
    m_task_queue.push(std::move(task));
    lock.unlock();
    EmitEvent(BlackboardEvent::TASK_SCHEDULED, task.id);
    m_task_cv.notify_one();
}

std::optional<Task> EnhancedBlackboard::GetNextTask() {
    std::unique_lock lock(m_mutex);
    
    if (m_task_queue.empty()) return std::nullopt;
    
    Task task = m_task_queue.top();
    m_task_queue.pop();
    task.started_time = std::chrono::system_clock::now();
    m_active_tasks[task.id] = task;
    
    return task;
}

void EnhancedBlackboard::MarkTaskComplete(const std::string& task_id,
                                          const std::unordered_map<std::string, float>& results) {
    std::unique_lock lock(m_mutex);
    auto it = m_active_tasks.find(task_id);
    if (it != m_active_tasks.end()) {
        it->second.completed = true;
        m_completed_tasks[task_id] = it->second;
        m_active_tasks.erase(it);
    }
    lock.unlock();
    EmitEvent(BlackboardEvent::TASK_COMPLETED, task_id);
}

void EnhancedBlackboard::MarkTaskFailed(const std::string& task_id, const std::string& reason) {
    std::unique_lock lock(m_mutex);
    auto it = m_active_tasks.find(task_id);
    if (it != m_active_tasks.end()) {
        it->second.failed = true;
        it->second.failure_reason = reason;
        m_failed_tasks[task_id] = it->second;
        m_active_tasks.erase(it);
    }
    lock.unlock();
    EmitEvent(BlackboardEvent::TASK_FAILED, task_id);
}

std::optional<Task> EnhancedBlackboard::GetTask(const std::string& task_id) const {
    std::shared_lock lock(m_mutex);
    
    auto it = m_active_tasks.find(task_id);
    if (it != m_active_tasks.end()) return it->second;
    
    auto comp_it = m_completed_tasks.find(task_id);
    if (comp_it != m_completed_tasks.end()) return comp_it->second;
    
    auto fail_it = m_failed_tasks.find(task_id);
    if (fail_it != m_failed_tasks.end()) return fail_it->second;
    
    return std::nullopt;
}

std::vector<Task> EnhancedBlackboard::GetPendingTasks() const {
    std::shared_lock lock(m_mutex);
    std::vector<Task> result;
    auto queue_copy = m_task_queue;
    while (!queue_copy.empty()) {
        result.push_back(queue_copy.top());
        queue_copy.pop();
    }
    return result;
}

std::vector<Task> EnhancedBlackboard::GetActiveTasks() const {
    std::shared_lock lock(m_mutex);
    std::vector<Task> result;
    for (const auto& [id, task] : m_active_tasks) {
        result.push_back(task);
    }
    return result;
}

std::vector<Task> EnhancedBlackboard::GetCompletedTasks() const {
    std::shared_lock lock(m_mutex);
    std::vector<Task> result;
    for (const auto& [id, task] : m_completed_tasks) {
        result.push_back(task);
    }
    return result;
}

std::vector<Task> EnhancedBlackboard::GetFailedTasks() const {
    std::shared_lock lock(m_mutex);
    std::vector<Task> result;
    for (const auto& [id, task] : m_failed_tasks) {
        result.push_back(task);
    }
    return result;
}

size_t EnhancedBlackboard::PendingTaskCount() const {
    std::shared_lock lock(m_mutex);
    return m_task_queue.size();
}

size_t EnhancedBlackboard::ActiveTaskCount() const {
    std::shared_lock lock(m_mutex);
    return m_active_tasks.size();
}

void EnhancedBlackboard::ClearTasks() {
    std::unique_lock lock(m_mutex);
    while (!m_task_queue.empty()) m_task_queue.pop();
    m_active_tasks.clear();
    m_completed_tasks.clear();
    m_failed_tasks.clear();
}

// ============================================================================
// Agent Performance Tracking
// ============================================================================

void EnhancedBlackboard::RegisterAgent(const std::string& agent_name,
                                      const std::vector<Capability>& capabilities) {
    std::unique_lock lock(m_mutex);
    m_agent_capabilities[agent_name] = capabilities;
    if (m_agent_performance.find(agent_name) == m_agent_performance.end()) {
        m_agent_performance[agent_name] = AgentPerformance{agent_name};
    }
}

void EnhancedBlackboard::UnregisterAgent(const std::string& agent_name) {
    std::unique_lock lock(m_mutex);
    m_agent_capabilities.erase(agent_name);
    m_agent_performance.erase(agent_name);
}

void EnhancedBlackboard::RecordAgentSuccess(const std::string& agent_name,
                                            const std::string& capability,
                                            Confidence confidence,
                                            float duration_ms) {
    std::unique_lock lock(m_mutex);
    auto& perf = m_agent_performance[agent_name];
    perf.agent_name = agent_name;
    perf.total_tasks++;
    perf.successful_tasks++;
    perf.average_confidence = (perf.average_confidence * (perf.total_tasks - 1) + confidence) / perf.total_tasks;
    perf.average_duration_ms = (perf.average_duration_ms * (perf.total_tasks - 1) + duration_ms) / perf.total_tasks;
    perf.last_executed = std::chrono::system_clock::now();
    perf.capability_scores[capability] = (perf.capability_scores[capability] * 0.9f) + 0.1f; // EMA
}

void EnhancedBlackboard::RecordAgentFailure(const std::string& agent_name,
                                            const std::string& capability,
                                            const std::string& reason) {
    std::unique_lock lock(m_mutex);
    auto& perf = m_agent_performance[agent_name];
    perf.agent_name = agent_name;
    perf.total_tasks++;
    perf.failed_tasks++;
    perf.capability_scores[capability] = perf.capability_scores[capability] * 0.9f; // EMA decay
}

std::optional<AgentPerformance> EnhancedBlackboard::GetAgentPerformance(const std::string& agent_name) const {
    std::shared_lock lock(m_mutex);
    auto it = m_agent_performance.find(agent_name);
    if (it != m_agent_performance.end()) return it->second;
    return std::nullopt;
}

std::vector<AgentPerformance> EnhancedBlackboard::GetAllAgentPerformance() const {
    std::shared_lock lock(m_mutex);
    std::vector<AgentPerformance> result;
    for (const auto& [name, perf] : m_agent_performance) {
        result.push_back(perf);
    }
    return result;
}

std::vector<std::string> EnhancedBlackboard::FindAgentsWithCapability(const std::string& capability) const {
    std::shared_lock lock(m_mutex);
    std::vector<std::string> result;
    for (const auto& [agent, caps] : m_agent_capabilities) {
        for (const auto& cap : caps) {
            if (cap.name == capability) {
                result.push_back(agent);
                break;
            }
        }
    }
    return result;
}

// ============================================================================
// Cognitive State
// ============================================================================

CognitiveState EnhancedBlackboard::GetCognitiveState() const {
    std::shared_lock lock(m_mutex);
    CognitiveState state;
    state.active_hypotheses = GetActiveHypotheses();
    state.recent_evidence = GetRecentEvidence(20);
    state.pending_tasks = GetPendingTasks();
    state.active_tasks = GetActiveTasks();
    state.current_focus = m_current_focus;
    state.current_phase = m_current_phase;
    state.last_update = m_last_update;
    state.total_reflections = m_total_reflections;
    state.total_replans = m_total_replans;
    
    for (const auto& [domain, conf] : state.confidence_by_domain) {
        state.confidence_by_domain[domain] = conf;
    }
    
    return state;
}

void EnhancedBlackboard::UpdateCognitiveState() {
    std::unique_lock lock(m_mutex);
    m_last_update = std::chrono::system_clock::now();
}

std::string EnhancedBlackboard::GetCurrentFocus() const {
    std::shared_lock lock(m_mutex);
    return m_current_focus;
}

void EnhancedBlackboard::SetCurrentFocus(const std::string& hypothesis_id) {
    std::unique_lock lock(m_mutex);
    m_current_focus = hypothesis_id;
}

std::string EnhancedBlackboard::GetCurrentPhase() const {
    std::shared_lock lock(m_mutex);
    return m_current_phase;
}

void EnhancedBlackboard::SetCurrentPhase(const std::string& phase) {
    std::unique_lock lock(m_mutex);
    m_current_phase = phase;
}

// ============================================================================
// Event Subscription
// ============================================================================

void EnhancedBlackboard::Subscribe(BlackboardEvent event, BlackboardCallback callback) {
    std::unique_lock lock(m_mutex);
    m_callbacks[event].push_back(std::move(callback));
}

void EnhancedBlackboard::Unsubscribe(BlackboardEvent event) {
    std::unique_lock lock(m_mutex);
    m_callbacks.erase(event);
}

void EnhancedBlackboard::Notify(BlackboardEvent event, const std::string& details) {
    EmitEvent(event, details);
}

// ============================================================================
// Mission Management
// ============================================================================

void EnhancedBlackboard::StartMission(const std::string& mission_id,
                                       const std::string& description,
                                       MissionType type) {
    std::unique_lock lock(m_mutex);
    MissionMetrics metrics;
    metrics.mission_id = mission_id;
    metrics.goal_description = description;
    metrics.type = type;
    metrics.start_time = std::chrono::system_clock::now();
    m_mission_metrics[mission_id] = std::move(metrics);
    lock.unlock();
    EmitEvent(BlackboardEvent::MISSION_STARTED, mission_id);
}

void EnhancedBlackboard::CompleteMission(const std::string& mission_id) {
    std::unique_lock lock(m_mutex);
    auto it = m_mission_metrics.find(mission_id);
    if (it != m_mission_metrics.end()) {
        it->second.end_time = std::chrono::system_clock::now();
    }
    lock.unlock();
    EmitEvent(BlackboardEvent::MISSION_COMPLETE, mission_id);
}

void EnhancedBlackboard::FailMission(const std::string& mission_id, const std::string& reason) {
    std::unique_lock lock(m_mutex);
    auto it = m_mission_metrics.find(mission_id);
    if (it != m_mission_metrics.end()) {
        it->second.end_time = std::chrono::system_clock::now();
        it->second.unresolved_questions.push_back(reason);
    }
}

std::optional<MissionMetrics> EnhancedBlackboard::GetMissionMetrics(const std::string& mission_id) const {
    std::shared_lock lock(m_mutex);
    auto it = m_mission_metrics.find(mission_id);
    if (it != m_mission_metrics.end()) return it->second;
    return std::nullopt;
}

std::vector<MissionMetrics> EnhancedBlackboard::GetAllMissionMetrics() const {
    std::shared_lock lock(m_mutex);
    std::vector<MissionMetrics> result;
    for (const auto& [id, metrics] : m_mission_metrics) {
        result.push_back(metrics);
    }
    return result;
}

// ============================================================================
// Utility
// ============================================================================

void EnhancedBlackboard::ClearAll() {
    std::unique_lock lock(m_mutex);
    m_evidence.clear();
    m_hypotheses.clear();
    while (!m_task_queue.empty()) m_task_queue.pop();
    m_active_tasks.clear();
    m_completed_tasks.clear();
    m_failed_tasks.clear();
    m_agent_performance.clear();
    m_agent_capabilities.clear();
    m_mission_metrics.clear();
    m_current_focus.clear();
    m_current_phase = "IDLE";
    m_total_reflections = 0;
    m_total_replans = 0;
}

std::string EnhancedBlackboard::DumpState() const {
    std::shared_lock lock(m_mutex);
    std::ostringstream oss;
    
    oss << "=== EnhancedBlackboard State ===\n";
    oss << "Evidence: " << m_evidence.size() << " items\n";
    oss << "Hypotheses: " << m_hypotheses.size() << " items\n";
    oss << "Pending Tasks: " << m_task_queue.size() << "\n";
    oss << "Active Tasks: " << m_active_tasks.size() << "\n";
    oss << "Completed Tasks: " << m_completed_tasks.size() << "\n";
    oss << "Failed Tasks: " << m_failed_tasks.size() << "\n";
    oss << "Registered Agents: " << m_agent_capabilities.size() << "\n";
    oss << "Current Focus: " << m_current_focus << "\n";
    oss << "Current Phase: " << m_current_phase << "\n";
    
    if (!m_hypotheses.empty()) {
        oss << "\n--- Active Hypotheses ---\n";
        for (const auto& [id, hyp] : m_hypotheses) {
            if (hyp.status != Hypothesis::Status::REFUTED && 
                hyp.status != Hypothesis::Status::DEPRECATED) {
                oss << "[" << StatusToString(hyp.status) << "] ";
                oss << hyp.claim << " (conf: " << std::fixed << std::setprecision(2) << hyp.confidence << ")\n";
            }
        }
    }
    
    return oss.str();
}

void EnhancedBlackboard::PruneLowConfidence(Confidence threshold) {
    std::unique_lock lock(m_mutex);
    for (auto it = m_evidence.begin(); it != m_evidence.end();) {
        if (it->second.confidence < threshold) {
            it = m_evidence.erase(it);
        } else {
            ++it;
        }
    }
}

void EnhancedBlackboard::PruneOldEvidence(std::chrono::hours age_limit) {
    std::unique_lock lock(m_mutex);
    auto cutoff = std::chrono::system_clock::now() - age_limit;
    for (auto it = m_evidence.begin(); it != m_evidence.end();) {
        if (it->second.timestamp < cutoff) {
            it = m_evidence.erase(it);
        } else {
            ++it;
        }
    }
}

// ============================================================================
// Internal Helpers
// ============================================================================

void EnhancedBlackboard::ResolveConflicts(const std::string& hypothesis_id) {
    auto hyp_it = m_hypotheses.find(hypothesis_id);
    if (hyp_it == m_hypotheses.end()) return;
    
    auto& hyp = hyp_it->second;
    
    // If contradicting evidence outweighs supporting, mark as refuted
    float supporting_weight = 0.0f;
    float contradicting_weight = 0.0f;
    
    for (const auto& ev_id : hyp.supporting_evidence) {
        auto ev_it = m_evidence.find(ev_id);
        if (ev_it != m_evidence.end()) {
            supporting_weight += ev_it->second.confidence * std::abs(ev_it->second.weight);
        }
    }
    
    for (const auto& ev_id : hyp.contradicting_evidence) {
        auto ev_it = m_evidence.find(ev_id);
        if (ev_it != m_evidence.end()) {
            contradicting_weight += ev_it->second.confidence * std::abs(ev_it->second.weight);
        }
    }
    
    if (contradicting_weight > supporting_weight * 1.5f && hyp.confidence < 0.3f) {
        hyp.status = Hypothesis::Status::REFUTED;
    }
}

Confidence EnhancedBlackboard::RecalculateHypothesisConfidence(const std::string& hypothesis_id) {
    auto hyp_it = m_hypotheses.find(hypothesis_id);
    if (hyp_it == m_hypotheses.end()) return 0.0f;
    
    auto& hyp = hyp_it->second;
    std::vector<std::string> all_evidence;
    all_evidence.insert(all_evidence.end(), hyp.supporting_evidence.begin(), hyp.supporting_evidence.end());
    all_evidence.insert(all_evidence.end(), hyp.contradicting_evidence.begin(), hyp.contradicting_evidence.end());
    
    hyp.confidence = AggregateConfidence(all_evidence, m_evidence);
    hyp.last_updated = std::chrono::system_clock::now();
    
    return hyp.confidence;
}

void EnhancedBlackboard::UpdateHypothesisTimestamp(const std::string& id) {
    auto it = m_hypotheses.find(id);
    if (it != m_hypotheses.end()) {
        it->second.last_updated = std::chrono::system_clock::now();
    }
}

void EnhancedBlackboard::EmitEvent(BlackboardEvent event, const std::string& details) {
    auto it = m_callbacks.find(event);
    if (it != m_callbacks.end()) {
        for (const auto& callback : it->second) {
            try {
                callback(event, details);
            } catch (...) {
                // Callback exceptions should not break the blackboard
            }
        }
    }
}

} // namespace rawrxd::cognitive
