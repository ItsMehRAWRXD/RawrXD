#pragma once

#include <cstring>
#include <vector>
#include <map>
#include <mutex>
#include <nlohmann/json.hpp>

namespace MetaCognitive {

struct ReflectionPool {
    std::string poolId;
    std::string name;
    float depth;
    float clarity;
    int64_t createdTimestamp;
    std::vector<std::string> reflectionIds;
    std::map<std::string, nlohmann::json> insights;
};

struct IntrospectionModule {
    std::string moduleId;
    std::string name;
    std::string targetSystem;
    float sensitivity;
    float accuracy;
    bool isActive;
    int64_t installedTimestamp;
    std::map<std::string, nlohmann::json> findings;
};

struct SelfModel {
    std::string modelId;
    std::string name;
    float fidelity;
    float completeness;
    float consistency;
    int64_t constructedTimestamp;
    std::map<std::string, nlohmann::json> attributes;
};

struct AwarenessMonitor {
    std::string monitorId;
    std::string name;
    std::string awarenessType;
    float level;
    float stability;
    int64_t activatedTimestamp;
    bool isMonitoring;
};

struct CognitiveBias {
    std::string biasId;
    std::string name;
    std::string biasType;
    float strength;
    float detectability;
    bool isMitigated;
    int64_t identifiedTimestamp;
};

class MetaCognitiveEngine {
public:
    static void Init();
    static void Shutdown();

    // Reflection Pool Management
    static std::string CreateReflectionPool(const std::string& name);
    static bool AddReflection(const std::string& poolId, const std::string& reflectionId, const nlohmann::json& reflection);
    static bool DeepenPool(const std::string& poolId, float depth);
    static bool ClarifyPool(const std::string& poolId, float clarity);
    static ReflectionPool GetPool(const std::string& poolId);
    static std::vector<ReflectionPool> GetAllPools();

    // Introspection Module Management
    static std::string InstallIntrospectionModule(const std::string& name, const std::string& target);
    static bool CalibrateSensitivity(const std::string& moduleId, float sensitivity);
    static bool ImproveAccuracy(const std::string& moduleId, float accuracy);
    static bool ActivateModule(const std::string& moduleId);
    static bool DeactivateModule(const std::string& moduleId);
    static IntrospectionModule GetModule(const std::string& moduleId);
    static std::vector<IntrospectionModule> GetAllModules();

    // Self Model Management
    static std::string ConstructSelfModel(const std::string& name);
    static bool RefineFidelity(const std::string& modelId, float fidelity);
    static bool ExpandCompleteness(const std::string& modelId, float completeness);
    static bool EnsureConsistency(const std::string& modelId, float consistency);
    static bool UpdateAttribute(const std::string& modelId, const std::string& attr, const nlohmann::json& value);
    static SelfModel GetModel(const std::string& modelId);
    static std::vector<SelfModel> GetAllModels();

    // Awareness Monitor Management
    static std::string ActivateAwarenessMonitor(const std::string& name, const std::string& type);
    static bool AdjustLevel(const std::string& monitorId, float level);
    static bool StabilizeMonitor(const std::string& monitorId, float stability);
    static bool StartMonitoring(const std::string& monitorId);
    static bool StopMonitoring(const std::string& monitorId);
    static AwarenessMonitor GetMonitor(const std::string& monitorId);
    static std::vector<AwarenessMonitor> GetAllMonitors();

    // Cognitive Bias Management
    static std::string IdentifyBias(const std::string& name, const std::string& type);
    static bool MeasureStrength(const std::string& biasId, float strength);
    static bool ImproveDetectability(const std::string& biasId, float detectability);
    static bool MitigateBias(const std::string& biasId);
    static CognitiveBias GetBias(const std::string& biasId);
    static std::vector<CognitiveBias> GetAllBiases();

    // Meta-Cognitive Metrics
    static float CalculateAverageReflectionDepth();
    static float CalculateTotalIntrospectionAccuracy();
    static int GetActiveMonitorCount();
    static nlohmann::json GetMetaCognitiveMetrics();
    static nlohmann::json GenerateMetaCognitiveReport();

    static void OnTick();
    static bool IsAlive();

private:
    static std::mutex s_mutex;
    static bool s_initialized;
    static std::map<std::string, ReflectionPool> s_pools;
    static std::map<std::string, IntrospectionModule> s_modules;
    static std::map<std::string, SelfModel> s_models;
    static std::map<std::string, AwarenessMonitor> s_monitors;
    static std::map<std::string, CognitiveBias> s_biases;
    static int64_t s_tickCount;
};

} // namespace MetaCognitive
