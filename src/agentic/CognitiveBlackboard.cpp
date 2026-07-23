// ============================================================================
// CognitiveBlackboard.cpp - Working memory implementation
// Part of RawrXD Cognitive Foundation (Phase 1)
// ============================================================================
#include "CognitiveBlackboard.hpp"
#include <algorithm>
#include <chrono>

namespace rawrxd::agentic {

// ============================================================================
// CognitiveState Implementation
// ============================================================================

nlohmann::json CognitiveState::ToJson() const {
    nlohmann::json j;
    j["current_focus"] = current_focus;
    j["current_phase"] = current_phase;
    j["mission_progress"] = mission_progress;
    j["total_evidence_count"] = total_evidence_count;
    j["total_hypothesis_count"] = total_hypothesis_count;
    j["confidence_by_domain"] = confidence_by_domain;
    
    auto time_t = std::chrono::system_clock::to_time_t(last_update);
    std::stringstream ss;
    ss << std::put_time(std::gmtime(&time_t), "%Y-%m-%dT%H:%M:%SZ");
    j["last_update"] = ss.str();
    
    // Serialize hypotheses
    j["active_hypotheses"] = nlohmann::json::array();
    for (const auto& h : active_hypotheses) {
        j["active_hypotheses"].push_back(h.ToJson());
    }
    
    // Serialize evidence
    j["recent_evidence"] = nlohmann::json::array();
    for (const auto& e : recent_evidence) {
        j["recent_evidence"].push_back(e.ToJson());
    }
    
    return j;
}

CognitiveState CognitiveState::FromJson(const nlohmann::json& j) {
    CognitiveState state;
    state.current_focus = j.value("current_focus", "");
    state.current_phase = j.value("current_phase", "");
    state.mission_progress = j.value("mission_progress", 0.0f);
    state.total_evidence_count = j.value("total_evidence_count", 0);
    state.total_hypothesis_count = j.value("total_hypothesis_count", 0);
    state.confidence_by_domain = j.value("confidence_by_domain", 
                                          std::unordered_map<std::string, float>{});
    
    // Parse active hypotheses
    if (j.contains("active_hypotheses")) {
        for (const auto& hj : j["active_hypotheses"]) {
            state.active_hypotheses.push_back(Hypothesis::FromJson(hj));
        }
    }
    
    // Parse recent evidence
    if (j.contains("recent_evidence")) {
        for (const auto& ej : j["recent_evidence"]) {
            state.recent_evidence.push_back(Evidence::FromJson(ej));
        }
    }
    
    return state;
}

// ============================================================================
// CognitiveBlackboard Implementation
// ============================================================================

CognitiveBlackboard::CognitiveBlackboard() 
    : m_last_update(std::chrono::system_clock::now()) 
{
}

CognitiveBlackboard::~CognitiveBlackboard() {
    // Notify all subscribers of shutdown
    for (auto& [event_type, callbacks] : m_subscribers) {
        callbacks.clear();
    }
    m_global_subscribers.clear();
}

// ==================== Evidence Management ====================

std::string CognitiveBlackboard::AddEvidence(Evidence&& ev) {
    std::unique_lock lock(m_mutex);
    
    // Generate ID if not provided
    if (ev.id.empty()) {
        ev.id = Evidence::GenerateId();
    }
    
    ev.timestamp = std::chrono::system_clock::now();
    
    // Store evidence
    std::string id = ev.id;
    m_evidence[id] = std::move(ev);
    
    // Update indexes
    UpdateIndexesForEvidence(m_evidence[id]);
    
    // Notify subscribers
    BlackboardEvent event{
        BlackboardEventType::EVIDENCE_ADDED,
        id,
        std::chrono::system_clock::now(),
        m_evidence[id].ToJson()
    };
    lock.unlock();
    NotifySubscribers(event);
    
    return id;
}

void CognitiveBlackboard::UpdateEvidenceConfidence(const std::string& id, float new_confidence) {
    std::unique_lock lock(m_mutex);
    
    auto it = m_evidence.find(id);
    if (it == m_evidence.end()) return;
    
    it->second.confidence = new_confidence;
    
    // Update any hypotheses that use this evidence
    for (auto& [hyp_id, hyp] : m_hypotheses) {
        bool needs_update = false;
        
        if (std::find(hyp.supporting_evidence.begin(), hyp.supporting_evidence.end(), id) != 
            hyp.supporting_evidence.end()) {
            needs_update = true;
        }
        if (std::find(hyp.contradicting_evidence.begin(), hyp.contradicting_evidence.end(), id) != 
            hyp.contradicting_evidence.end()) {
            needs_update = true;
        }
        
        if (needs_update) {
            hyp.UpdateConfidence(m_evidence);
        }
    }
    
    BlackboardEvent event{
        BlackboardEventType::EVIDENCE_UPDATED,
        id,
        std::chrono::system_clock::now(),
        it->second.ToJson()
    };
    lock.unlock();
    NotifySubscribers(event);
}

void CognitiveBlackboard::UpdateEvidenceWeight(const std::string& id, float new_weight) {
    std::unique_lock lock(m_mutex);
    
    auto it = m_evidence.find(id);
    if (it == m_evidence.end()) return;
    
    it->second.weight = new_weight;
    
    BlackboardEvent event{
        BlackboardEventType::EVIDENCE_UPDATED,
        id,
        std::chrono::system_clock::now(),
        it->second.ToJson()
    };
    lock.unlock();
    NotifySubscribers(event);
}

std::optional<Evidence> CognitiveBlackboard::GetEvidence(const std::string& id) const {
    std::shared_lock lock(m_mutex);
    
    auto it = m_evidence.find(id);
    if (it != m_evidence.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::vector<Evidence> CognitiveBlackboard::GetEvidenceForHypothesis(const std::string& hypothesis_id) const {
    std::shared_lock lock(m_mutex);
    
    std::vector<Evidence> result;
    
    auto it = m_hypotheses.find(hypothesis_id);
    if (it == m_hypotheses.end()) return result;
    
    const auto& hyp = it->second;
    
    // Collect supporting evidence
    for (const auto& ev_id : hyp.supporting_evidence) {
        auto ev_it = m_evidence.find(ev_id);
        if (ev_it != m_evidence.end()) {
            result.push_back(ev_it->second);
        }
    }
    
    // Collect contradicting evidence
    for (const auto& ev_id : hyp.contradicting_evidence) {
        auto ev_it = m_evidence.find(ev_id);
        if (ev_it != m_evidence.end()) {
            result.push_back(ev_it->second);
        }
    }
    
    return result;
}

std::vector<Evidence> CognitiveBlackboard::GetEvidenceBySource(const std::string& agent_name) const {
    std::shared_lock lock(m_mutex);
    
    std::vector<Evidence> result;
    
    auto it = m_evidence_by_source.find(agent_name);
    if (it == m_evidence_by_source.end()) return result;
    
    for (const auto& ev_id : it->second) {
        auto ev_it = m_evidence.find(ev_id);
        if (ev_it != m_evidence.end()) {
            result.push_back(ev_it->second);
        }
    }
    
    return result;
}

std::vector<Evidence> CognitiveBlackboard::GetEvidenceByType(EvidenceType type) const {
    std::shared_lock lock(m_mutex);
    
    std::vector<Evidence> result;
    
    auto it = m_evidence_by_type.find(type);
    if (it == m_evidence_by_type.end()) return result;
    
    for (const auto& ev_id : it->second) {
        auto ev_it = m_evidence.find(ev_id);
        if (ev_it != m_evidence.end()) {
            result.push_back(ev_it->second);
        }
    }
    
    return result;
}

std::vector<Evidence> CognitiveBlackboard::GetRecentEvidence(size_t count) const {
    std::shared_lock lock(m_mutex);
    
    std::vector<Evidence> result;
    result.reserve(std::min(count, m_evidence.size()));
    
    // Copy all evidence
    for (const auto& [id, ev] : m_evidence) {
        result.push_back(ev);
    }
    
    // Sort by timestamp (most recent first)
    std::sort(result.begin(), result.end(), 
              [](const Evidence& a, const Evidence& b) {
                  return a.timestamp > b.timestamp;
              });
    
    // Trim to count
    if (result.size() > count) {
        result.resize(count);
    }
    
    return result;
}

std::unordered_map<std::string, float> CognitiveBlackboard::GetConfidenceMap() const {
    std::shared_lock lock(m_mutex);
    
    std::unordered_map<std::string, float> result;
    for (const auto& [id, ev] : m_evidence) {
        result[id] = ev.confidence;
    }
    return result;
}

// ==================== Hypothesis Management ====================

std::string CognitiveBlackboard::CreateHypothesis(const std::string& description, 
                                                    MissionGoal goal_type,
                                                    float confidence_threshold) {
    std::unique_lock lock(m_mutex);
    
    Hypothesis hyp(description, goal_type, confidence_threshold);
    hyp.created_by_agent = "MissionDirector";
    
    std::string id = hyp.id;
    m_hypotheses[id] = std::move(hyp);
    
    // Update indexes
    UpdateIndexesForHypothesis(m_hypotheses[id]);
    
    // Set as current focus if no focus exists
    if (m_current_focus.empty()) {
        m_current_focus = id;
    }
    
    BlackboardEvent event{
        BlackboardEventType::HYPOTHESIS_CREATED,
        id,
        std::chrono::system_clock::now(),
        m_hypotheses[id].ToJson()
    };
    lock.unlock();
    NotifySubscribers(event);
    
    return id;
}

void CognitiveBlackboard::UpdateHypothesis(const std::string& id, 
                                          const std::vector<std::string>& supporting,
                                          const std::vector<std::string>& contradicting) {
    std::unique_lock lock(m_mutex);
    
    auto it = m_hypotheses.find(id);
    if (it == m_hypotheses.end()) return;
    
    auto& hyp = it->second;
    
    // Update evidence lists
    for (const auto& ev_id : supporting) {
        if (std::find(hyp.supporting_evidence.begin(), hyp.supporting_evidence.end(), ev_id) == 
            hyp.supporting_evidence.end()) {
            hyp.supporting_evidence.push_back(ev_id);
        }
    }
    
    for (const auto& ev_id : contradicting) {
        if (std::find(hyp.contradicting_evidence.begin(), hyp.contradicting_evidence.end(), ev_id) == 
            hyp.contradicting_evidence.end()) {
            hyp.contradicting_evidence.push_back(ev_id);
        }
    }
    
    // Recalculate confidence
    hyp.UpdateConfidence(m_evidence);
    
    // Determine event type
    BlackboardEventType event_type = BlackboardEventType::HYPOTHESIS_UPDATED;
    if (hyp.status == HypothesisStatus::CONFIRMED) {
        event_type = BlackboardEventType::HYPOTHESIS_CONFIRMED;
    } else if (hyp.status == HypothesisStatus::REFUTED) {
        event_type = BlackboardEventType::HYPOTHESIS_REFUTED;
    }
    
    // Check if confidence threshold reached
    if (hyp.confidence >= hyp.confidence_threshold && 
        hyp.status == HypothesisStatus::UNVERIFIED) {
        event_type = BlackboardEventType::CONFIDENCE_THRESHOLD_REACHED;
    }
    
    BlackboardEvent event{
        event_type,
        id,
        std::chrono::system_clock::now(),
        hyp.ToJson()
    };
    lock.unlock();
    NotifySubscribers(event);
}

void CognitiveBlackboard::ProposeAction(const std::string& hypothesis_id, const std::string& action) {
    std::unique_lock lock(m_mutex);
    
    auto it = m_hypotheses.find(hypothesis_id);
    if (it == m_hypotheses.end()) return;
    
    it->second.proposed_next_action = action;
    it->second.status = HypothesisStatus::UNDER_VERIFICATION;
    it->second.last_updated = std::chrono::system_clock::now();
}

void CognitiveBlackboard::SetHypothesisPriority(const std::string& id, int priority) {
    std::unique_lock lock(m_mutex);
    
    auto it = m_hypotheses.find(id);
    if (it == m_hypotheses.end()) return;
    
    it->second.priority = priority;
}

std::optional<Hypothesis> CognitiveBlackboard::GetHypothesis(const std::string& id) const {
    std::shared_lock lock(m_mutex);
    
    auto it = m_hypotheses.find(id);
    if (it != m_hypotheses.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::vector<Hypothesis> CognitiveBlackboard::GetActiveHypotheses() const {
    std::shared_lock lock(m_mutex);
    
    std::vector<Hypothesis> result;
    for (const auto& [id, hyp] : m_hypotheses) {
        if (hyp.status == HypothesisStatus::UNVERIFIED || 
            hyp.status == HypothesisStatus::UNDER_VERIFICATION) {
            result.push_back(hyp);
        }
    }
    return result;
}

std::vector<Hypothesis> CognitiveBlackboard::GetHypothesesByGoal(MissionGoal goal) const {
    std::shared_lock lock(m_mutex);
    
    std::vector<Hypothesis> result;
    
    auto it = m_hypotheses_by_goal.find(goal);
    if (it == m_hypotheses_by_goal.end()) return result;
    
    for (const auto& hyp_id : it->second) {
        auto hyp_it = m_hypotheses.find(hyp_id);
        if (hyp_it != m_hypotheses.end()) {
            result.push_back(hyp_it->second);
        }
    }
    
    return result;
}

std::vector<Hypothesis> CognitiveBlackboard::GetHypothesesByStatus(HypothesisStatus status) const {
    std::shared_lock lock(m_mutex);
    
    std::vector<Hypothesis> result;
    
    auto it = m_hypotheses_by_status.find(status);
    if (it == m_hypotheses_by_status.end()) return result;
    
    for (const auto& hyp_id : it->second) {
        auto hyp_it = m_hypotheses.find(hyp_id);
        if (hyp_it != m_hypotheses.end()) {
            result.push_back(hyp_it->second);
        }
    }
    
    return result;
}

std::optional<Hypothesis> CognitiveBlackboard::GetMostConfidentHypothesis() const {
    std::shared_lock lock(m_mutex);
    
    std::optional<Hypothesis> best;
    float best_confidence = -1.0f;
    
    for (const auto& [id, hyp] : m_hypotheses) {
        if (hyp.confidence > best_confidence) {
            best = hyp;
            best_confidence = hyp.confidence;
        }
    }
    
    return best;
}

std::optional<Hypothesis> CognitiveBlackboard::GetHypothesisRequiringAction() const {
    std::shared_lock lock(m_mutex);
    
    std::optional<Hypothesis> best;
    int best_priority = -1;
    
    for (const auto& [id, hyp] : m_hypotheses) {
        if (hyp.IsActionable() && hyp.priority > best_priority) {
            best = hyp;
            best_priority = hyp.priority;
        }
    }
    
    return best;
}

void CognitiveBlackboard::SetCurrentFocus(const std::string& hypothesis_id) {
    std::unique_lock lock(m_mutex);
    m_current_focus = hypothesis_id;
}

// ==================== Cognitive State ====================

CognitiveState CognitiveBlackboard::GetCognitiveState() const {
    std::shared_lock lock(m_mutex);
    
    CognitiveState state;
    state.current_focus = m_current_focus;
    state.current_phase = m_current_phase;
    state.mission_progress = 0.0f;  // Would need mission context
    state.total_evidence_count = m_evidence.size();
    state.total_hypothesis_count = m_hypotheses.size();
    state.last_update = m_last_update;
    
    // Get active hypotheses
    for (const auto& [id, hyp] : m_hypotheses) {
        if (hyp.IsActionable()) {
            state.active_hypotheses.push_back(hyp);
        }
    }
    
    // Get recent evidence
    state.recent_evidence = GetRecentEvidence(20);
    
    // Calculate confidence by domain
    for (const auto& [id, hyp] : m_hypotheses) {
        std::string domain = HypothesisUtils::GoalToString(hyp.goal_type);
        auto it = state.confidence_by_domain.find(domain);
        if (it == state.confidence_by_domain.end()) {
            state.confidence_by_domain[domain] = hyp.confidence;
        } else {
            // Average confidence
            it->second = (it->second + hyp.confidence) / 2.0f;
        }
    }
    
    return state;
}

void CognitiveBlackboard::UpdateCognitiveState() {
    std::unique_lock lock(m_mutex);
    m_last_update = std::chrono::system_clock::now();
}

void CognitiveBlackboard::SetMissionPhase(const std::string& phase) {
    std::unique_lock lock(m_mutex);
    m_current_phase = phase;
    m_last_update = std::chrono::system_clock::now();
    
    BlackboardEvent event{
        BlackboardEventType::MISSION_PHASE_CHANGED,
        "",
        std::chrono::system_clock::now(),
        {{"phase", phase}}
    };
    lock.unlock();
    NotifySubscribers(event);
}

void CognitiveBlackboard::SetMissionProgress(float progress) {
    std::unique_lock lock(m_mutex);
    // Would update mission progress tracking
}

// ==================== Event Notifications ====================

void CognitiveBlackboard::Subscribe(BlackboardEventType event_type, BlackboardCallback callback) {
    std::unique_lock lock(m_mutex);
    m_subscribers[event_type].push_back(callback);
}

void CognitiveBlackboard::SubscribeToAll(BlackboardCallback callback) {
    std::unique_lock lock(m_mutex);
    m_global_subscribers.push_back(callback);
}

void CognitiveBlackboard::Unsubscribe(BlackboardEventType event_type) {
    std::unique_lock lock(m_mutex);
    m_subscribers[event_type].clear();
}

void CognitiveBlackboard::NotifySubscribers(const BlackboardEvent& event) {
    // Notify specific subscribers
    auto it = m_subscribers.find(event.type);
    if (it != m_subscribers.end()) {
        for (const auto& callback : it->second) {
            try {
                callback(event);
            } catch (...) {
                // Log error but continue
            }
        }
    }
    
    // Notify global subscribers
    for (const auto& callback : m_global_subscribers) {
        try {
            callback(event);
        } catch (...) {
            // Log error but continue
        }
    }
}

// ==================== Conflict Resolution ====================

std::vector<std::pair<std::string, std::string>> CognitiveBlackboard::FindConflictingHypotheses() const {
    std::shared_lock lock(m_mutex);
    
    std::vector<std::pair<std::string, std::string>> conflicts;
    
    for (const auto& [id1, hyp1] : m_hypotheses) {
        for (const auto& [id2, hyp2] : m_hypotheses) {
            if (id1 >= id2) continue;
            
            // Same goal type but different = potential conflict
            if (hyp1.goal_type == hyp2.goal_type && 
                hyp1.id != hyp2.id &&
                hyp1.confidence > 0.5f && hyp2.confidence > 0.5f) {
                conflicts.emplace_back(id1, id2);
            }
        }
    }
    
    return conflicts;
}

void CognitiveBlackboard::ResolveConflict(const std::string& hypothesis_a, 
                                         const std::string& hypothesis_b) {
    std::unique_lock lock(m_mutex);
    
    auto it_a = m_hypotheses.find(hypothesis_a);
    auto it_b = m_hypotheses.find(hypothesis_b);
    
    if (it_a == m_hypotheses.end() || it_b == m_hypotheses.end()) return;
    
    // Keep the one with higher confidence, mark other as superseded
    if (it_a->second.confidence >= it_b->second.confidence) {
        it_b->second.status = HypothesisStatus::SUPERSEDED;
        it_b->second.superseded_by = hypothesis_a;
    } else {
        it_a->second.status = HypothesisStatus::SUPERSEDED;
        it_a->second.superseded_by = hypothesis_b;
    }
}

// ==================== Pruning ====================

void CognitiveBlackboard::PruneLowConfidence(float threshold, std::chrono::hours age_limit) {
    std::unique_lock lock(m_mutex);
    
    auto now = std::chrono::system_clock::now();
    
    // Prune evidence
    for (auto it = m_evidence.begin(); it != m_evidence.end();) {
        const auto& ev = it->second;
        auto age = std::chrono::duration_cast<std::chrono::hours>(now - ev.timestamp);
        
        if (ev.confidence < threshold && age > age_limit) {
            it = m_evidence.erase(it);
        } else {
            ++it;
        }
    }
    
    // Prune refuted hypotheses
    for (auto it = m_hypotheses.begin(); it != m_hypotheses.end();) {
        const auto& hyp = it->second;
        auto age = std::chrono::duration_cast<std::chrono::hours>(now - hyp.last_updated);
        
        if (hyp.status == HypothesisStatus::REFUTED && age > age_limit) {
            it = m_hypotheses.erase(it);
        } else {
            ++it;
        }
    }
    
    // Rebuild indexes
    RebuildIndexes();
}

void CognitiveBlackboard::PruneRefutedHypotheses() {
    std::unique_lock lock(m_mutex);
    
    for (auto it = m_hypotheses.begin(); it != m_hypotheses.end();) {
        if (it->second.status == HypothesisStatus::REFUTED) {
            it = m_hypotheses.erase(it);
        } else {
            ++it;
        }
    }
    
    RebuildIndexes();
}

// ==================== Statistics ====================

size_t CognitiveBlackboard::EvidenceCount() const {
    std::shared_lock lock(m_mutex);
    return m_evidence.size();
}

size_t CognitiveBlackboard::HypothesisCount() const {
    std::shared_lock lock(m_mutex);
    return m_hypotheses.size();
}

size_t CognitiveBlackboard::ActiveHypothesisCount() const {
    std::shared_lock lock(m_mutex);
    
    size_t count = 0;
    for (const auto& [id, hyp] : m_hypotheses) {
        if (hyp.IsActionable()) {
            count++;
        }
    }
    return count;
}

float CognitiveBlackboard::AverageConfidence() const {
    std::shared_lock lock(m_mutex);
    
    if (m_hypotheses.empty()) return 0.0f;
    
    float sum = 0.0f;
    for (const auto& [id, hyp] : m_hypotheses) {
        sum += hyp.confidence;
    }
    
    return sum / m_hypotheses.size();
}

// ==================== Serialization ====================

nlohmann::json CognitiveBlackboard::ToJson() const {
    std::shared_lock lock(m_mutex);
    
    nlohmann::json j;
    j["current_focus"] = m_current_focus;
    j["current_phase"] = m_current_phase;
    
    // Serialize evidence
    j["evidence"] = nlohmann::json::array();
    for (const auto& [id, ev] : m_evidence) {
        j["evidence"].push_back(ev.ToJson());
    }
    
    // Serialize hypotheses
    j["hypotheses"] = nlohmann::json::array();
    for (const auto& [id, hyp] : m_hypotheses) {
        j["hypotheses"].push_back(hyp.ToJson());
    }
    
    return j;
}

void CognitiveBlackboard::FromJson(const nlohmann::json& j) {
    std::unique_lock lock(m_mutex);
    
    Clear();
    
    m_current_focus = j.value("current_focus", "");
    m_current_phase = j.value("current_phase", "");
    
    // Deserialize evidence
    if (j.contains("evidence")) {
        for (const auto& ej : j["evidence"]) {
            Evidence ev = Evidence::FromJson(ej);
            m_evidence[ev.id] = std::move(ev);
        }
    }
    
    // Deserialize hypotheses
    if (j.contains("hypotheses")) {
        for (const auto& hj : j["hypotheses"]) {
            Hypothesis hyp = Hypothesis::FromJson(hj);
            m_hypotheses[hyp.id] = std::move(hyp);
        }
    }
    
    // Rebuild indexes
    RebuildIndexes();
}

void CognitiveBlackboard::Clear() {
    std::unique_lock lock(m_mutex);
    
    m_evidence.clear();
    m_hypotheses.clear();
    m_evidence_by_source.clear();
    m_evidence_by_type.clear();
    m_hypotheses_by_goal.clear();
    m_hypotheses_by_status.clear();
    m_current_focus.clear();
    m_current_phase = "INITIALIZING";
}

// ==================== Helper Methods ====================

void CognitiveBlackboard::UpdateIndexesForEvidence(const Evidence& ev) {
    // Update source index
    m_evidence_by_source[ev.source_agent].push_back(ev.id);
    
    // Update type index
    m_evidence_by_type[ev.type].push_back(ev.id);
}

void CognitiveBlackboard::UpdateIndexesForHypothesis(const Hypothesis& hyp) {
    // Update goal index
    m_hypotheses_by_goal[hyp.goal_type].push_back(hyp.id);
    
    // Update status index
    m_hypotheses_by_status[hyp.status].push_back(hyp.id);
}

void CognitiveBlackboard::RebuildIndexes() {
    m_evidence_by_source.clear();
    m_evidence_by_type.clear();
    m_hypotheses_by_goal.clear();
    m_hypotheses_by_status.clear();
    
    for (const auto& [id, ev] : m_evidence) {
        UpdateIndexesForEvidence(ev);
    }
    
    for (const auto& [id, hyp] : m_hypotheses) {
        UpdateIndexesForHypothesis(hyp);
    }
}

} // namespace rawrxd::agentic
