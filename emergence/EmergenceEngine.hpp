#pragma once

#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <nlohmann/json.hpp>

namespace RawrXD {
namespace Sovereign {
namespace Emergence {

struct EmergentPattern {
    std::string patternId;
    std::string name;
    std::string description;
    std::vector<std::string> componentLayers;
    std::map<std::string, float> characteristics;
    float stability;
    bool isSelfSustaining;
    int64_t emergedAt;
};

struct SelfOrganizingStructure {
    std::string structureId;
    std::string type;
    std::vector<std::string> memberAgents;
    std::map<std::string, std::string> rules;
    float organizationLevel;
    bool isStable;
    int64_t formedAt;
};

struct AdaptiveBehavior {
    std::string behaviorId;
    std::string name;
    std::string trigger;
    std::string response;
    float effectiveness;
    int usageCount;
    bool isLearned;
};

class EmergenceEngine {
public:
    static void Init();
    static void OnTick();
    static bool IsAlive();

    static std::string DetectPattern(const std::string& name,
                                      const std::vector<std::string>& componentLayers);
    static bool StabilizePattern(const std::string& patternId);
    static bool DissolvePattern(const std::string& patternId);
    
    static std::string FormStructure(const std::string& type,
                                      const std::vector<std::string>& memberAgents);
    static bool EvolveStructure(const std::string& structureId);
    static bool DissolveStructure(const std::string& structureId);
    
    static std::string LearnBehavior(const std::string& name,
                                      const std::string& trigger,
                                      const std::string& response);
    static bool ReinforceBehavior(const std::string& behaviorId);
    static bool ExecuteBehavior(const std::string& behaviorId);
    
    static std::vector<std::string> GetEmergingPatterns();
    static std::vector<std::string> GetStablePatterns();
    static float CalculateSystemEntropy();
    static float CalculateOrganizationLevel();
    static float CalculateAdaptability();
    
    static nlohmann::json GetPattern(const std::string& patternId);
    static nlohmann::json GetPatterns();
    static nlohmann::json GetStructure(const std::string& structureId);
    static nlohmann::json GetStructures();
    static nlohmann::json GetBehavior(const std::string& behaviorId);
    static nlohmann::json GetBehaviors();
    
    static nlohmann::json GetEmergenceMetrics();
    static nlohmann::json GenerateEmergenceReport();

private:
    static std::vector<EmergentPattern> s_patterns;
    static std::vector<SelfOrganizingStructure> s_structures;
    static std::vector<AdaptiveBehavior> s_behaviors;
    static std::mutex s_mutex;
    static bool s_alive;
    
    static EmergentPattern* FindPattern(const std::string& patternId);
    static SelfOrganizingStructure* FindStructure(const std::string& structureId);
    static AdaptiveBehavior* FindBehavior(const std::string& behaviorId);
    static void SpontaneousGeneration();
};

} // namespace Emergence
} // namespace Sovereign
} // namespace RawrXD
