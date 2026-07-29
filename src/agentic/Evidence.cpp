// ============================================================================
// Evidence.cpp - Implementation of Evidence and EvidenceUtils
// Part of RawrXD Cognitive Foundation (Phase 1)
// ============================================================================
#include "Evidence.hpp"
#include <chrono>
#include <sstream>
#include <iomanip>

namespace rawrxd::agentic {

// Generate unique ID using timestamp and random component
std::string Evidence::GenerateId() {
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();
    
    static thread_local int counter = 0;
    counter++;
    
    std::ostringstream oss;
    oss << "EV-" << ms << "-" << counter;
    return oss.str();
}

Evidence::Evidence(const std::string& desc, const std::string& agent, float conf)
    : id(GenerateId())
    , description(desc)
    , source_agent(agent)
    , confidence(conf)
    , timestamp(std::chrono::system_clock::now())
{
}

nlohmann::json Evidence::ToJson() const {
    nlohmann::json j;
    j["id"] = id;
    j["description"] = description;
    j["source_agent"] = source_agent;
    j["type"] = static_cast<int>(type);
    j["confidence"] = confidence;
    j["weight"] = weight;
    
    auto time_t = std::chrono::system_clock::to_time_t(timestamp);
    std::stringstream ss;
    ss << std::put_time(std::gmtime(&time_t), "%Y-%m-%dT%H:%M:%SZ");
    j["timestamp"] = ss.str();
    
    j["metadata"] = metadata;
    j["supports"] = supports;
    j["contradicts"] = contradicts;
    j["related_to"] = related_to;
    
    // Serialize content based on type
    if (std::holds_alternative<std::string>(content)) {
        j["content_type"] = "string";
        j["content"] = std::get<std::string>(content);
    } else if (std::holds_alternative<nlohmann::json>(content)) {
        j["content_type"] = "json";
        j["content"] = std::get<nlohmann::json>(content);
    } else if (std::holds_alternative<double>(content)) {
        j["content_type"] = "numeric";
        j["content"] = std::get<double>(content);
    }
    // Binary content not serialized to JSON (would need base64)
    
    return j;
}

Evidence Evidence::FromJson(const nlohmann::json& j) {
    Evidence ev;
    ev.id = j.value("id", "");
    ev.description = j.value("description", "");
    ev.source_agent = j.value("source_agent", "");
    ev.type = static_cast<EvidenceType>(j.value("type", 0));
    ev.confidence = j.value("confidence", 0.5f);
    ev.weight = j.value("weight", 1.0f);
    
    // Parse timestamp
    std::string ts_str = j.value("timestamp", "");
    if (!ts_str.empty()) {
        std::tm tm = {};
        std::stringstream ss(ts_str);
        ss >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
        ev.timestamp = std::chrono::system_clock::from_time_t(std::mktime(&tm));
    } else {
        ev.timestamp = std::chrono::system_clock::now();
    }
    
    ev.metadata = j.value("metadata", std::unordered_map<std::string, std::string>{});
    ev.supports = j.value("supports", std::vector<std::string>{});
    ev.contradicts = j.value("contradicts", std::vector<std::string>{});
    ev.related_to = j.value("related_to", std::vector<std::string>{});
    
    // Deserialize content
    std::string content_type = j.value("content_type", "string");
    if (content_type == "string") {
        ev.content = j.value("content", "");
    } else if (content_type == "json") {
        ev.content = j.value("content", nlohmann::json{});
    } else if (content_type == "numeric") {
        ev.content = j.value("content", 0.0);
    }
    
    return ev;
}

std::string Evidence::GetContentString() const {
    if (std::holds_alternative<std::string>(content)) {
        return std::get<std::string>(content);
    } else if (std::holds_alternative<nlohmann::json>(content)) {
        return std::get<nlohmann::json>(content).dump();
    } else if (std::holds_alternative<double>(content)) {
        return std::to_string(std::get<double>(content));
    }
    return "[binary content]";
}

// ============================================================================
// EvidenceUtils Implementation
// ============================================================================

float EvidenceUtils::AggregateConfidence(const std::vector<std::string>& evidence_ids,
                                         const std::unordered_map<std::string, Evidence>& pool) {
    if (evidence_ids.empty()) {
        return 0.0f;
    }
    
    // Weighted average of confidence scores
    float total_weight = 0.0f;
    float weighted_sum = 0.0f;
    
    for (const auto& id : evidence_ids) {
        auto it = pool.find(id);
        if (it != pool.end()) {
            const auto& ev = it->second;
            float w = std::abs(ev.weight);  // Use absolute weight
            weighted_sum += ev.confidence * w;
            total_weight += w;
        }
    }
    
    if (total_weight > 0.0f) {
        return weighted_sum / total_weight;
    }
    return 0.0f;
}

std::vector<std::pair<std::string, std::string>> EvidenceUtils::FindConflicts(
    const std::unordered_map<std::string, Evidence>& pool) {
    
    std::vector<std::pair<std::string, std::string>> conflicts;
    
    for (const auto& [id1, ev1] : pool) {
        for (const auto& [id2, ev2] : pool) {
            if (id1 >= id2) continue;  // Avoid duplicates
            
            // Check if they contradict each other
            bool conflict = false;
            
            // Direct contradiction
            if (std::find(ev1.contradicts.begin(), ev1.contradicts.end(), id2) != ev1.contradicts.end() ||
                std::find(ev2.contradicts.begin(), ev2.contradicts.end(), id1) != ev2.contradicts.end()) {
                conflict = true;
            }
            
            // Weight-based contradiction (one strongly supports, other strongly contradicts same target)
            if (ev1.weight > 0.5f && ev2.weight < -0.5f && 
                !ev1.supports.empty() && !ev2.contradicts.empty()) {
                // Check if they target the same hypothesis (would need external context)
                // Flag high-confidence opposing evidence as potential conflict
                if (ev1.confidence > 0.7f && ev2.confidence > 0.7f) {
                    conflict = true;
                }
            }
            
            if (conflict) {
                conflicts.emplace_back(id1, id2);
            }
        }
    }
    
    return conflicts;
}

std::chrono::seconds EvidenceUtils::GetAge(const Evidence& ev) {
    auto now = std::chrono::system_clock::now();
    return std::chrono::duration_cast<std::chrono::seconds>(now - ev.timestamp);
}

} // namespace rawrxd::agentic
