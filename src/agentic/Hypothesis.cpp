// ============================================================================
// Hypothesis.cpp - Implementation of Hypothesis and HypothesisUtils
// Part of RawrXD Cognitive Foundation (Phase 1)
// ============================================================================
#include "Hypothesis.hpp"
#include <chrono>
#include <sstream>
#include <iomanip>
#include <math>

namespace rawrxd::agentic {

// Generate unique ID
std::string Hypothesis::GenerateId() {
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();
    
    static thread_local int counter = 0;
    counter++;
    
    std::ostringstream oss;
    oss << "HYP-" << ms << "-" << counter;
    return oss.str();
}

Hypothesis::Hypothesis(const std::string& desc, MissionGoal goal, float threshold)
    : id(GenerateId())
    , description(desc)
    , goal_type(goal)
    , confidence_threshold(threshold)
    , created(std::chrono::system_clock::now())
    , last_updated(created)
{
}

void Hypothesis::UpdateConfidence(const std::unordered_map<std::string, Evidence>& evidence_pool) {
    if (supporting_evidence.empty() && contradicting_evidence.empty()) {
        confidence = bayesian_prior;
        return;
    }
    
    // Calculate weighted confidence from supporting evidence
    float supporting_sum = 0.0f;
    float supporting_weight = 0.0f;
    
    for (const auto& ev_id : supporting_evidence) {
        auto it = evidence_pool.find(ev_id);
        if (it != evidence_pool.end()) {
            const auto& ev = it->second;
            supporting_sum += ev.confidence * ev.weight;
            supporting_weight += ev.weight;
        }
    }
    
    // Calculate weighted confidence from contradicting evidence
    float contradicting_sum = 0.0f;
    float contradicting_weight = 0.0f;
    
    for (const auto& ev_id : contradicting_evidence) {
        auto it = evidence_pool.find(ev_id);
        if (it != evidence_pool.end()) {
            const auto& ev = it->second;
            // Invert confidence for contradicting evidence
            contradicting_sum += (1.0f - ev.confidence) * ev.weight;
            contradicting_weight += ev.weight;
        }
    }
    
    // Bayesian update
    float supporting_conf = supporting_weight > 0 ? supporting_sum / supporting_weight : 0.0f;
    float contradicting_conf = contradicting_weight > 0 ? contradicting_sum / contradicting_weight : 0.0f;
    
    // Combine with prior
    float likelihood = (supporting_conf * (1.0f - contradicting_conf)) / 
                       ((supporting_conf * (1.0f - contradicting_conf)) + 
                        ((1.0f - supporting_conf) * contradicting_conf) + 0.001f);
    
    confidence = (bayesian_prior * likelihood) / 
                 ((bayesian_prior * likelihood) + ((1.0f - bayesian_prior) * (1.0f - likelihood)));
    
    // Clamp to [0, 1]
    confidence = std::max(0.0f, std::min(1.0f, confidence));
    
    last_updated = std::chrono::system_clock::now();
    revision++;
    
    // Update status based on confidence
    if (confidence >= confidence_threshold && status == HypothesisStatus::UNVERIFIED) {
        status = HypothesisStatus::CONFIRMED;
    } else if (confidence < 0.2f && status == HypothesisStatus::UNVERIFIED) {
        status = HypothesisStatus::REFUTED;
    }
}

bool Hypothesis::IsActionable() const {
    return status == HypothesisStatus::UNVERIFIED || 
           status == HypothesisStatus::UNDER_VERIFICATION;
}

bool Hypothesis::NeedsVerification() const {
    return status == HypothesisStatus::UNVERIFIED && 
           confidence >= confidence_threshold * 0.5f;
}

nlohmann::json Hypothesis::ToJson() const {
    nlohmann::json j;
    j["id"] = id;
    j["description"] = description;
    j["goal_type"] = static_cast<int>(goal_type);
    j["status"] = static_cast<int>(status);
    j["confidence"] = confidence;
    j["confidence_threshold"] = confidence_threshold;
    j["bayesian_prior"] = bayesian_prior;
    j["supporting_evidence"] = supporting_evidence;
    j["contradicting_evidence"] = contradicting_evidence;
    j["pending_verification"] = pending_verification;
    j["proposed_next_action"] = proposed_next_action;
    j["required_capabilities"] = required_capabilities;
    j["priority"] = priority;
    j["revision"] = revision;
    j["alternative_hypotheses"] = alternative_hypotheses;
    j["superseded_by"] = superseded_by;
    
    auto time_t = std::chrono::system_clock::to_time_t(created);
    std::stringstream ss;
    ss << std::put_time(std::gmtime(&time_t), "%Y-%m-%dT%H:%M:%SZ");
    j["created"] = ss.str();
    
    time_t = std::chrono::system_clock::to_time_t(last_updated);
    ss.str("");
    ss << std::put_time(std::gmtime(&time_t), "%Y-%m-%dT%H:%M:%SZ");
    j["last_updated"] = ss.str();
    
    return j;
}

Hypothesis Hypothesis::FromJson(const nlohmann::json& j) {
    Hypothesis hyp;
    hyp.id = j.value("id", "");
    hyp.description = j.value("description", "");
    hyp.goal_type = static_cast<MissionGoal>(j.value("goal_type", 0));
    hyp.status = static_cast<HypothesisStatus>(j.value("status", 0));
    hyp.confidence = j.value("confidence", 0.0f);
    hyp.confidence_threshold = j.value("confidence_threshold", 0.7f);
    hyp.bayesian_prior = j.value("bayesian_prior", 0.5f);
    hyp.supporting_evidence = j.value("supporting_evidence", std::vector<std::string>{});
    hyp.contradicting_evidence = j.value("contradicting_evidence", std::vector<std::string>{});
    hyp.pending_verification = j.value("pending_verification", std::vector<std::string>{});
    hyp.proposed_next_action = j.value("proposed_next_action", "");
    hyp.required_capabilities = j.value("required_capabilities", std::vector<std::string>{});
    hyp.priority = j.value("priority", 50);
    hyp.revision = j.value("revision", 0);
    hyp.alternative_hypotheses = j.value("alternative_hypotheses", std::vector<std::string>{});
    hyp.superseded_by = j.value("superseded_by", "");
    
    // Parse timestamps
    std::string created_str = j.value("created", "");
    if (!created_str.empty()) {
        std::tm tm = {};
        std::stringstream ss(created_str);
        ss >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
        hyp.created = std::chrono::system_clock::from_time_t(std::mktime(&tm));
    }
    
    std::string updated_str = j.value("last_updated", "");
    if (!updated_str.empty()) {
        std::tm tm = {};
        std::stringstream ss(updated_str);
        ss >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
        hyp.last_updated = std::chrono::system_clock::from_time_t(std::mktime(&tm));
    }
    
    return hyp;
}

// ============================================================================
// HypothesisUtils Implementation
// ============================================================================

std::vector<std::string> HypothesisUtils::FindCompeting(
    const std::string& hypothesis_id,
    const std::unordered_map<std::string, Hypothesis>& pool) {
    
    std::vector<std::string> competing;
    
    auto it = pool.find(hypothesis_id);
    if (it == pool.end()) {
        return competing;
    }
    
    const auto& hyp = it->second;
    
    for (const auto& [id, other] : pool) {
        if (id == hypothesis_id) continue;
        
        // Same goal type = competing
        if (other.goal_type == hyp.goal_type) {
            competing.push_back(id);
        }
    }
    
    return competing;
}

std::string HypothesisUtils::SelectBest(
    const std::vector<std::string>& hypothesis_ids,
    const std::unordered_map<std::string, Hypothesis>& pool) {
    
    std::string best_id;
    float best_confidence = -1.0f;
    int best_priority = -1;
    
    for (const auto& id : hypothesis_ids) {
        auto it = pool.find(id);
        if (it == pool.end()) continue;
        
        const auto& hyp = it->second;
        
        // Prefer higher confidence, then higher priority
        if (hyp.confidence > best_confidence ||
            (hyp.confidence == best_confidence && hyp.priority > best_priority)) {
            best_id = id;
            best_confidence = hyp.confidence;
            best_priority = hyp.priority;
        }
    }
    
    return best_id;
}

float HypothesisUtils::CalculateConsensus(
    const std::vector<std::string>& hypothesis_ids,
    const std::unordered_map<std::string, Hypothesis>& pool) {
    
    if (hypothesis_ids.empty()) {
        return 0.0f;
    }
    
    float sum = 0.0f;
    for (const auto& id : hypothesis_ids) {
        auto it = pool.find(id);
        if (it != pool.end()) {
            sum += it->second.confidence;
        }
    }
    
    return sum / hypothesis_ids.size();
}

std::string HypothesisUtils::GoalToString(MissionGoal goal) {
    switch (goal) {
        case MissionGoal::EXTRACT_C2: return "EXTRACT_C2";
        case MissionGoal::IDENTIFY_MALWARE: return "IDENTIFY_MALWARE";
        case MissionGoal::REVERSE_PROTOCOL: return "REVERSE_PROTOCOL";
        case MissionGoal::FIND_VULNERABILITY: return "FIND_VULNERABILITY";
        case MissionGoal::UNPACK_BINARY: return "UNPACK_BINARY";
        case MissionGoal::ANALYZE_CRYPTO: return "ANALYZE_CRYPTO";
        case MissionGoal::TRACE_EXECUTION: return "TRACE_EXECUTION";
        case MissionGoal::EXFILTRATION_PATTERN: return "EXFILTRATION_PATTERN";
        case MissionGoal::RECOVER_CONFIG: return "RECOVER_CONFIG";
        case MissionGoal::MAP_API_USAGE: return "MAP_API_USAGE";
        default: return "UNKNOWN";
    }
}

MissionGoal HypothesisUtils::StringToGoal(const std::string& str) {
    if (str == "EXTRACT_C2") return MissionGoal::EXTRACT_C2;
    if (str == "IDENTIFY_MALWARE") return MissionGoal::IDENTIFY_MALWARE;
    if (str == "REVERSE_PROTOCOL") return MissionGoal::REVERSE_PROTOCOL;
    if (str == "FIND_VULNERABILITY") return MissionGoal::FIND_VULNERABILITY;
    if (str == "UNPACK_BINARY") return MissionGoal::UNPACK_BINARY;
    if (str == "ANALYZE_CRYPTO") return MissionGoal::ANALYZE_CRYPTO;
    if (str == "TRACE_EXECUTION") return MissionGoal::TRACE_EXECUTION;
    if (str == "EXFILTRATION_PATTERN") return MissionGoal::EXFILTRATION_PATTERN;
    if (str == "RECOVER_CONFIG") return MissionGoal::RECOVER_CONFIG;
    if (str == "MAP_API_USAGE") return MissionGoal::MAP_API_USAGE;
    return MissionGoal::UNKNOWN;
}

} // namespace rawrxd::agentic
