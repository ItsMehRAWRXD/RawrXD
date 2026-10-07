#include "emergence/EmergenceEngine.hpp"
#include <chrono>
#include <algorithm>
#include <random>

namespace RawrXD {
namespace Sovereign {
namespace Emergence {

std::vector<EmergentPattern> EmergenceEngine::s_patterns;
std::vector<SelfOrganizingStructure> EmergenceEngine::s_structures;
std::vector<AdaptiveBehavior> EmergenceEngine::s_behaviors;
std::mutex EmergenceEngine::s_mutex;
bool EmergenceEngine::s_alive = false;

void EmergenceEngine::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    s_patterns.clear();
    s_structures.clear();
    s_behaviors.clear();
    s_alive = true;
}

void EmergenceEngine::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_alive) return;
    
    // Spontaneous generation of new patterns
    SpontaneousGeneration();
    
    // Evolve existing structures
    for (auto& structure : s_structures) {
        if (structure.isStable) {
            structure.organizationLevel = std::min(1.0f, structure.organizationLevel + 0.001f);
        } else {
            structure.organizationLevel *= 0.99f;
            if (structure.organizationLevel < 0.1f) {
                structure.isStable = false;
            }
        }
    }
    
    // Update pattern stability
    for (auto& pattern : s_patterns) {
        if (pattern.stability > 0.7f) {
            pattern.isSelfSustaining = true;
        }
        pattern.stability *= 0.9999f; // Gradual decay without reinforcement
    }
    
    // Clean up unstable structures
    s_structures.erase(
        std::remove_if(s_structures.begin(), s_structures.end(),
            [](const SelfOrganizingStructure& s) { return !s.isStable && s.organizationLevel < 0.05f; }),
        s_structures.end()
    );
}

bool EmergenceEngine::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_alive;
}

std::string EmergenceEngine::DetectPattern(const std::string& name,
                                            const std::vector<std::string>& componentLayers) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    EmergentPattern pattern;
    pattern.patternId = "pattern_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    pattern.name = name;
    pattern.componentLayers = componentLayers;
    pattern.stability = 0.5f;
    pattern.isSelfSustaining = false;
    pattern.emergedAt = std::chrono::steady_clock::now().time_since_epoch().count();
    
    // Generate characteristics based on component layers
    for (const auto& layer : componentLayers) {
        pattern.characteristics[layer + "_influence"] = 0.5f + (std::rand() % 50) / 100.0f;
    }
    
    s_patterns.push_back(pattern);
    return pattern.patternId;
}

bool EmergenceEngine::StabilizePattern(const std::string& patternId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    EmergentPattern* pattern = FindPattern(patternId);
    if (!pattern) return false;
    
    pattern->stability = std::min(1.0f, pattern->stability + 0.2f);
    if (pattern->stability > 0.8f) {
        pattern->isSelfSustaining = true;
    }
    return true;
}

bool EmergenceEngine::DissolvePattern(const std::string& patternId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    auto it = std::remove_if(s_patterns.begin(), s_patterns.end(),
        [&patternId](const EmergentPattern& p) { return p.patternId == patternId; });
    
    if (it != s_patterns.end()) {
        s_patterns.erase(it, s_patterns.end());
        return true;
    }
    return false;
}

std::string EmergenceEngine::FormStructure(const std::string& type,
                                            const std::vector<std::string>& memberAgents) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    SelfOrganizingStructure structure;
    structure.structureId = "structure_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    structure.type = type;
    structure.memberAgents = memberAgents;
    structure.organizationLevel = 0.3f;
    structure.isStable = true;
    structure.formedAt = std::chrono::steady_clock::now().time_since_epoch().count();
    
    // Generate self-organizing rules
    structure.rules["coordination"] = "decentralized";
    structure.rules["decision_making"] = "consensus";
    structure.rules["resource_allocation"] = "need_based";
    
    s_structures.push_back(structure);
    return structure.structureId;
}

bool EmergenceEngine::EvolveStructure(const std::string& structureId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    SelfOrganizingStructure* structure = FindStructure(structureId);
    if (!structure) return false;
    
    // Evolution: add new rules or modify existing ones
    structure->rules["adaptation"] = "continuous";
    structure->organizationLevel = std::min(1.0f, structure->organizationLevel + 0.1f);
    
    return true;
}

bool EmergenceEngine::DissolveStructure(const std::string& structureId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    auto it = std::remove_if(s_structures.begin(), s_structures.end(),
        [&structureId](const SelfOrganizingStructure& s) { return s.structureId == structureId; });
    
    if (it != s_structures.end()) {
        s_structures.erase(it, s_structures.end());
        return true;
    }
    return false;
}

std::string EmergenceEngine::LearnBehavior(const std::string& name,
                                            const std::string& trigger,
                                            const std::string& response) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    AdaptiveBehavior behavior;
    behavior.behaviorId = "behavior_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    behavior.name = name;
    behavior.trigger = trigger;
    behavior.response = response;
    behavior.effectiveness = 0.5f;
    behavior.usageCount = 0;
    behavior.isLearned = true;
    
    s_behaviors.push_back(behavior);
    return behavior.behaviorId;
}

bool EmergenceEngine::ReinforceBehavior(const std::string& behaviorId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    AdaptiveBehavior* behavior = FindBehavior(behaviorId);
    if (!behavior) return false;
    
    behavior->usageCount++;
    behavior->effectiveness = std::min(1.0f, behavior->effectiveness + 0.05f);
    return true;
}

bool EmergenceEngine::ExecuteBehavior(const std::string& behaviorId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    AdaptiveBehavior* behavior = FindBehavior(behaviorId);
    if (!behavior) return false;
    
    behavior->usageCount++;
    return true;
}

std::vector<std::string> EmergenceEngine::GetEmergingPatterns() {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<std::string> emerging;
    
    for (const auto& pattern : s_patterns) {
        if (!pattern.isSelfSustaining && pattern.stability > 0.3f) {
            emerging.push_back(pattern.patternId);
        }
    }
    
    return emerging;
}

std::vector<std::string> EmergenceEngine::GetStablePatterns() {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<std::string> stable;
    
    for (const auto& pattern : s_patterns) {
        if (pattern.isSelfSustaining) {
            stable.push_back(pattern.patternId);
        }
    }
    
    return stable;
}

float EmergenceEngine::CalculateSystemEntropy() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    // Entropy increases with number of unstable patterns and structures
    float entropy = 0.0f;
    
    for (const auto& pattern : s_patterns) {
        if (!pattern.isSelfSustaining) {
            entropy += 1.0f - pattern.stability;
        }
    }
    
    for (const auto& structure : s_structures) {
        if (!structure.isStable) {
            entropy += 1.0f - structure.organizationLevel;
        }
    }
    
    return std::min(1.0f, entropy / 10.0f);
}

float EmergenceEngine::CalculateOrganizationLevel() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    if (s_structures.empty()) return 0.0f;
    
    float totalOrg = 0.0f;
    for (const auto& structure : s_structures) {
        totalOrg += structure.organizationLevel;
    }
    
    return totalOrg / s_structures.size();
}

float EmergenceEngine::CalculateAdaptability() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    if (s_behaviors.empty()) return 0.0f;
    
    float totalAdaptability = 0.0f;
    for (const auto& behavior : s_behaviors) {
        totalAdaptability += behavior.effectiveness * std::min(1.0f, behavior.usageCount / 10.0f);
    }
    
    return totalAdaptability / s_behaviors.size();
}

nlohmann::json EmergenceEngine::GetPattern(const std::string& patternId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    EmergentPattern* pattern = FindPattern(patternId);
    if (!pattern) return nlohmann::json{{"error", "pattern not found"}};
    
    nlohmann::json j;
    j["patternId"] = pattern->patternId;
    j["name"] = pattern->name;
    j["componentLayers"] = pattern->componentLayers;
    j["characteristics"] = pattern->characteristics;
    j["stability"] = pattern->stability;
    j["isSelfSustaining"] = pattern->isSelfSustaining;
    j["emergedAt"] = pattern->emergedAt;
    return j;
}

nlohmann::json EmergenceEngine::GetPatterns() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    nlohmann::json patterns = nlohmann::json::array();
    for (const auto& pattern : s_patterns) {
        nlohmann::json j;
        j["patternId"] = pattern.patternId;
        j["name"] = pattern.name;
        j["stability"] = pattern.stability;
        j["isSelfSustaining"] = pattern.isSelfSustaining;
        patterns.push_back(j);
    }
    return patterns;
}

nlohmann::json EmergenceEngine::GetStructure(const std::string& structureId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    SelfOrganizingStructure* structure = FindStructure(structureId);
    if (!structure) return nlohmann::json{{"error", "structure not found"}};
    
    nlohmann::json j;
    j["structureId"] = structure->structureId;
    j["type"] = structure->type;
    j["memberAgents"] = structure->memberAgents;
    j["rules"] = structure->rules;
    j["organizationLevel"] = structure->organizationLevel;
    j["isStable"] = structure->isStable;
    j["formedAt"] = structure->formedAt;
    return j;
}

nlohmann::json EmergenceEngine::GetStructures() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    nlohmann::json structures = nlohmann::json::array();
    for (const auto& structure : s_structures) {
        nlohmann::json j;
        j["structureId"] = structure.structureId;
        j["type"] = structure.type;
        j["memberCount"] = structure.memberAgents.size();
        j["organizationLevel"] = structure.organizationLevel;
        j["isStable"] = structure.isStable;
        structures.push_back(j);
    }
    return structures;
}

nlohmann::json EmergenceEngine::GetBehavior(const std::string& behaviorId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    AdaptiveBehavior* behavior = FindBehavior(behaviorId);
    if (!behavior) return nlohmann::json{{"error", "behavior not found"}};
    
    nlohmann::json j;
    j["behaviorId"] = behavior->behaviorId;
    j["name"] = behavior->name;
    j["trigger"] = behavior->trigger;
    j["response"] = behavior->response;
    j["effectiveness"] = behavior->effectiveness;
    j["usageCount"] = behavior->usageCount;
    j["isLearned"] = behavior->isLearned;
    return j;
}

nlohmann::json EmergenceEngine::GetBehaviors() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    nlohmann::json behaviors = nlohmann::json::array();
    for (const auto& behavior : s_behaviors) {
        nlohmann::json j;
        j["behaviorId"] = behavior.behaviorId;
        j["name"] = behavior.name;
        j["effectiveness"] = behavior.effectiveness;
        j["usageCount"] = behavior.usageCount;
        behaviors.push_back(j);
    }
    return behaviors;
}

nlohmann::json EmergenceEngine::GetEmergenceMetrics() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    nlohmann::json metrics;
    metrics["totalPatterns"] = s_patterns.size();
    metrics["totalStructures"] = s_structures.size();
    metrics["totalBehaviors"] = s_behaviors.size();
    metrics["emergingPatterns"] = GetEmergingPatterns().size();
    metrics["stablePatterns"] = GetStablePatterns().size();
    metrics["systemEntropy"] = CalculateSystemEntropy();
    metrics["organizationLevel"] = CalculateOrganizationLevel();
    metrics["adaptability"] = CalculateAdaptability();
    
    return metrics;
}

nlohmann::json EmergenceEngine::GenerateEmergenceReport() {
    nlohmann::json report;
    report["metrics"] = GetEmergenceMetrics();
    report["patterns"] = GetPatterns();
    report["structures"] = GetStructures();
    report["behaviors"] = GetBehaviors();
    report["status"] = "emergence_active";
    report["timestamp"] = std::chrono::steady_clock::now().time_since_epoch().count();
    return report;
}

EmergentPattern* EmergenceEngine::FindPattern(const std::string& patternId) {
    for (auto& pattern : s_patterns) {
        if (pattern.patternId == patternId) return &pattern;
    }
    return nullptr;
}

SelfOrganizingStructure* EmergenceEngine::FindStructure(const std::string& structureId) {
    for (auto& structure : s_structures) {
        if (structure.structureId == structureId) return &structure;
    }
    return nullptr;
}

AdaptiveBehavior* EmergenceEngine::FindBehavior(const std::string& behaviorId) {
    for (auto& behavior : s_behaviors) {
        if (behavior.behaviorId == behaviorId) return &behavior;
    }
    return nullptr;
}

void EmergenceEngine::SpontaneousGeneration() {
    // Random chance to generate new patterns
    if (std::rand() % 1000 < 5) { // 0.5% chance per tick
        std::vector<std::string> possibleLayers = {
            "Fabric", "Cognition", "Federation", "Society", "Teleology",
            "Knowledge", "Ethics", "Aesthetics", "Spirituality", "Unity"
        };
        
        // Randomly select 2-4 layers
        std::vector<std::string> selectedLayers;
        int count = 2 + (std::rand() % 3);
        for (int i = 0; i < count; i++) {
            selectedLayers.push_back(possibleLayers[std::rand() % possibleLayers.size()]);
        }
        
        DetectPattern("AutoGenerated_" + std::to_string(std::rand()), selectedLayers);
    }
}

} // namespace Emergence
} // namespace Sovereign
} // namespace RawrXD
