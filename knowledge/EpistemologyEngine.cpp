#include "knowledge/EpistemologyEngine.hpp"
#include <chrono>
#include <algorithm>

namespace RawrXD {
namespace Sovereign {
namespace Knowledge {

std::vector<Belief> EpistemologyEngine::s_beliefs;
std::vector<Evidence> EpistemologyEngine::s_evidence;
std::vector<Justification> EpistemologyEngine::s_justifications;
std::mutex EpistemologyEngine::s_mutex;
bool EpistemologyEngine::s_alive = false;

void EpistemologyEngine::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    s_beliefs.clear();
    s_evidence.clear();
    s_justifications.clear();
    s_alive = true;
}

void EpistemologyEngine::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_alive) return;
    
    // Decay belief confidence over time if not reinforced
    for (auto& belief : s_beliefs) {
        if (belief.isActive && belief.confidence > 0.01f) {
            belief.confidence *= 0.99995f;
        }
    }
}

bool EpistemologyEngine::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_alive;
}

std::string EpistemologyEngine::FormBelief(const std::string& proposition,
                                           float initialConfidence,
                                           const std::string& source) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    Belief belief;
    belief.beliefId = "belief_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    belief.proposition = proposition;
    belief.confidence = std::max(0.0f, std::min(1.0f, initialConfidence));
    belief.source = source;
    belief.formedAt = std::chrono::steady_clock::now().time_since_epoch().count();
    belief.lastUpdated = belief.formedAt;
    belief.isActive = true;
    
    s_beliefs.push_back(belief);
    return belief.beliefId;
}

bool EpistemologyEngine::UpdateBeliefConfidence(const std::string& beliefId, float delta) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    Belief* belief = FindBelief(beliefId);
    if (!belief) return false;
    
    belief->confidence = std::max(0.0f, std::min(1.0f, belief->confidence + delta));
    belief->lastUpdated = std::chrono::steady_clock::now().time_since_epoch().count();
    return true;
}

bool EpistemologyEngine::ReviseBelief(const std::string& beliefId, const std::string& newProposition) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    Belief* belief = FindBelief(beliefId);
    if (!belief) return false;
    
    belief->proposition = newProposition;
    belief->lastUpdated = std::chrono::steady_clock::now().time_since_epoch().count();
    return true;
}

bool EpistemologyEngine::RetractBelief(const std::string& beliefId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    Belief* belief = FindBelief(beliefId);
    if (!belief) return false;
    
    belief->isActive = false;
    return true;
}

std::string EpistemologyEngine::AddEvidence(const std::string& description,
                                            const std::string& type,
                                            float weight,
                                            bool supports) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    Evidence evidence;
    evidence.evidenceId = "evidence_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    evidence.description = description;
    evidence.type = type;
    evidence.weight = weight;
    evidence.supports = supports;
    evidence.recordedAt = std::chrono::steady_clock::now().time_since_epoch().count();
    evidence.isActive = true;
    
    s_evidence.push_back(evidence);
    return evidence.evidenceId;
}

bool EpistemologyEngine::AttachEvidence(const std::string& beliefId, const std::string& evidenceId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    Belief* belief = FindBelief(beliefId);
    Evidence* evidence = FindEvidence(evidenceId);
    
    if (!belief || !evidence) return false;
    
    belief->evidenceIds.push_back(evidenceId);
    UpdateBeliefFromEvidence(*belief);
    return true;
}

bool EpistemologyEngine::DetachEvidence(const std::string& beliefId, const std::string& evidenceId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    Belief* belief = FindBelief(beliefId);
    if (!belief) return false;
    
    auto it = std::remove(belief->evidenceIds.begin(), belief->evidenceIds.end(), evidenceId);
    if (it != belief->evidenceIds.end()) {
        belief->evidenceIds.erase(it, belief->evidenceIds.end());
        UpdateBeliefFromEvidence(*belief);
        return true;
    }
    return false;
}

std::string EpistemologyEngine::CreateJustification(const std::string& beliefId,
                                                    const std::string& reasoning,
                                                    const std::vector<std::string>& premiseIds) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    Justification justification;
    justification.justificationId = "justification_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    justification.beliefId = beliefId;
    justification.reasoning = reasoning;
    justification.premiseIds = premiseIds;
    justification.coherenceScore = 1.0f;
    justification.createdAt = std::chrono::steady_clock::now().time_since_epoch().count();
    
    s_justifications.push_back(justification);
    return justification.justificationId;
}

float EpistemologyEngine::EvaluateCoherence(const std::string& beliefId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    Belief* belief = FindBelief(beliefId);
    if (!belief) return 0.0f;
    
    // Calculate coherence based on evidence
    float totalWeight = 0.0f;
    float supportingWeight = 0.0f;
    
    for (const auto& evidenceId : belief->evidenceIds) {
        Evidence* evidence = FindEvidence(evidenceId);
        if (evidence && evidence->isActive) {
            totalWeight += evidence->weight;
            if (evidence->supports) {
                supportingWeight += evidence->weight;
            }
        }
    }
    
    if (totalWeight == 0.0f) return belief->confidence;
    return supportingWeight / totalWeight;
}

std::vector<std::string> EpistemologyEngine::FindConflictingBeliefs(const std::string& beliefId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<std::string> conflicts;
    
    Belief* belief = FindBelief(beliefId);
    if (!belief) return conflicts;
    
    // Simple conflict detection: beliefs with contradictory propositions
    for (const auto& other : s_beliefs) {
        if (other.beliefId != beliefId && other.isActive) {
            // Check for negation patterns (simplified)
            if (other.proposition.find("not " + belief->proposition) != std::string::npos ||
                belief->proposition.find("not " + other.proposition) != std::string::npos) {
                conflicts.push_back(other.beliefId);
            }
        }
    }
    
    return conflicts;
}

std::vector<std::string> EpistemologyEngine::FindSupportingBeliefs(const std::string& beliefId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<std::string> supporting;
    
    Belief* belief = FindBelief(beliefId);
    if (!belief) return supporting;
    
    // Find beliefs that share evidence or premises
    for (const auto& other : s_beliefs) {
        if (other.beliefId != beliefId && other.isActive) {
            // Check for shared evidence
            for (const auto& evidenceId : belief->evidenceIds) {
                if (std::find(other.evidenceIds.begin(), other.evidenceIds.end(), evidenceId) != other.evidenceIds.end()) {
                    supporting.push_back(other.beliefId);
                    break;
                }
            }
        }
    }
    
    return supporting;
}

nlohmann::json EpistemologyEngine::GetBelief(const std::string& beliefId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    Belief* belief = FindBelief(beliefId);
    if (!belief) return nlohmann::json{{"error", "belief not found"}};
    
    nlohmann::json j;
    j["beliefId"] = belief->beliefId;
    j["proposition"] = belief->proposition;
    j["confidence"] = belief->confidence;
    j["evidenceIds"] = belief->evidenceIds;
    j["source"] = belief->source;
    j["formedAt"] = belief->formedAt;
    j["lastUpdated"] = belief->lastUpdated;
    j["isActive"] = belief->isActive;
    return j;
}

nlohmann::json EpistemologyEngine::GetBeliefs() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    nlohmann::json beliefs = nlohmann::json::array();
    for (const auto& belief : s_beliefs) {
        if (belief.isActive) {
            nlohmann::json j;
            j["beliefId"] = belief.beliefId;
            j["proposition"] = belief.proposition;
            j["confidence"] = belief.confidence;
            j["evidenceCount"] = belief.evidenceIds.size();
            beliefs.push_back(j);
        }
    }
    return beliefs;
}

nlohmann::json EpistemologyEngine::GetEvidence(const std::string& evidenceId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    Evidence* evidence = FindEvidence(evidenceId);
    if (!evidence) return nlohmann::json{{"error", "evidence not found"}};
    
    nlohmann::json j;
    j["evidenceId"] = evidence->evidenceId;
    j["description"] = evidence->description;
    j["type"] = evidence->type;
    j["weight"] = evidence->weight;
    j["supports"] = evidence->supports;
    j["recordedAt"] = evidence->recordedAt;
    j["isActive"] = evidence->isActive;
    return j;
}

nlohmann::json EpistemologyEngine::GetBeliefEvidence(const std::string& beliefId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    Belief* belief = FindBelief(beliefId);
    if (!belief) return nlohmann::json{{"error", "belief not found"}};
    
    nlohmann::json evidence = nlohmann::json::array();
    for (const auto& evidenceId : belief->evidenceIds) {
        Evidence* ev = FindEvidence(evidenceId);
        if (ev) {
            nlohmann::json j;
            j["evidenceId"] = ev->evidenceId;
            j["description"] = ev->description;
            j["type"] = ev->type;
            j["weight"] = ev->weight;
            j["supports"] = ev->supports;
            evidence.push_back(j);
        }
    }
    return evidence;
}

nlohmann::json EpistemologyEngine::GetJustification(const std::string& justificationId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    Justification* justification = FindJustification(justificationId);
    if (!justification) return nlohmann::json{{"error", "justification not found"}};
    
    nlohmann::json j;
    j["justificationId"] = justification->justificationId;
    j["beliefId"] = justification->beliefId;
    j["reasoning"] = justification->reasoning;
    j["premiseIds"] = justification->premiseIds;
    j["coherenceScore"] = justification->coherenceScore;
    j["createdAt"] = justification->createdAt;
    return j;
}

nlohmann::json EpistemologyEngine::QueryBeliefs(const std::string& query) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    nlohmann::json results = nlohmann::json::array();
    for (const auto& belief : s_beliefs) {
        if (belief.isActive && belief.proposition.find(query) != std::string::npos) {
            nlohmann::json j;
            j["beliefId"] = belief.beliefId;
            j["proposition"] = belief.proposition;
            j["confidence"] = belief.confidence;
            results.push_back(j);
        }
    }
    return results;
}

nlohmann::json EpistemologyEngine::GetEpistemologyMetrics() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    nlohmann::json metrics;
    metrics["totalBeliefs"] = s_beliefs.size();
    metrics["totalEvidence"] = s_evidence.size();
    metrics["totalJustifications"] = s_justifications.size();
    
    size_t activeBeliefs = 0;
    float avgConfidence = 0.0f;
    for (const auto& belief : s_beliefs) {
        if (belief.isActive) activeBeliefs++;
        avgConfidence += belief.confidence;
    }
    
    metrics["activeBeliefs"] = activeBeliefs;
    metrics["averageConfidence"] = s_beliefs.empty() ? 0.0f : avgConfidence / s_beliefs.size();
    return metrics;
}

nlohmann::json EpistemologyEngine::GetBeliefNetwork() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    nlohmann::json network;
    nlohmann::json nodes = nlohmann::json::array();
    nlohmann::json edges = nlohmann::json::array();
    
    for (const auto& belief : s_beliefs) {
        if (belief.isActive) {
            nlohmann::json node;
            node["id"] = belief.beliefId;
            node["proposition"] = belief.proposition;
            node["confidence"] = belief.confidence;
            nodes.push_back(node);
        }
    }
    
    // Create edges based on shared evidence
    for (size_t i = 0; i < s_beliefs.size(); i++) {
        for (size_t j = i + 1; j < s_beliefs.size(); j++) {
            if (!s_beliefs[i].isActive || !s_beliefs[j].isActive) continue;
            
            for (const auto& evidenceId : s_beliefs[i].evidenceIds) {
                if (std::find(s_beliefs[j].evidenceIds.begin(), s_beliefs[j].evidenceIds.end(), evidenceId) != s_beliefs[j].evidenceIds.end()) {
                    nlohmann::json edge;
                    edge["source"] = s_beliefs[i].beliefId;
                    edge["target"] = s_beliefs[j].beliefId;
                    edge["type"] = "shared_evidence";
                    edges.push_back(edge);
                    break;
                }
            }
        }
    }
    
    network["nodes"] = nodes;
    network["edges"] = edges;
    return network;
}

Belief* EpistemologyEngine::FindBelief(const std::string& beliefId) {
    for (auto& belief : s_beliefs) {
        if (belief.beliefId == beliefId) return &belief;
    }
    return nullptr;
}

Evidence* EpistemologyEngine::FindEvidence(const std::string& evidenceId) {
    for (auto& evidence : s_evidence) {
        if (evidence.evidenceId == evidenceId) return &evidence;
    }
    return nullptr;
}

Justification* EpistemologyEngine::FindJustification(const std::string& justificationId) {
    for (auto& justification : s_justifications) {
        if (justification.justificationId == justificationId) return &justification;
    }
    return nullptr;
}

void EpistemologyEngine::UpdateBeliefFromEvidence(Belief& belief) {
    float totalWeight = 0.0f;
    float supportingWeight = 0.0f;
    
    for (const auto& evidenceId : belief.evidenceIds) {
        Evidence* evidence = FindEvidence(evidenceId);
        if (evidence && evidence->isActive) {
            totalWeight += evidence->weight;
            if (evidence->supports) {
                supportingWeight += evidence->weight;
            }
        }
    }
    
    if (totalWeight > 0.0f) {
        float evidenceConfidence = supportingWeight / totalWeight;
        belief.confidence = belief.confidence * 0.7f + evidenceConfidence * 0.3f;
        belief.confidence = std::max(0.0f, std::min(1.0f, belief.confidence));
    }
}

} // namespace Knowledge
} // namespace Sovereign
} // namespace RawrXD
