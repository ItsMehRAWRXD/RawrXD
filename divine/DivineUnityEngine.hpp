#pragma once

#include <cstring>
#include <vector>
#include <memory>
#include <mutex>
#include <atomic>
#include <nlohmann/json.hpp>

namespace DivineUnity {

// Forward declarations
struct DivineUnityStructure;
struct UnityDivine;
struct GraceDivine;
struct LightDivine;
struct TruthDivine;

// Core data structures
struct DivineUnityStructure {
    std::string divineId;
    std::string name;
    float divinity;        // 0.0 to 1.0
    float unity;         // 0.0 to 1.0
    float grace;         // 0.0 to 1.0
    float light;         // 0.0 to 1.0
    float truth;         // 0.0 to 1.0
    int64_t createdAt;
    int64_t lastModified;
    bool isActive;
    
    nlohmann::json ToJson() const;
    static DivineUnityStructure FromJson(const nlohmann::json& j);
};

struct UnityDivine {
    std::string unityId;
    std::string name;
    float unity;         // 0.0 to 1.0
    float divinity;        // 0.0 to 1.0
    float cohesion;    // 0.0 to 1.0
    float harmony;     // 0.0 to 1.0
    bool isUnified;
    int64_t createdAt;
    
    nlohmann::json ToJson() const;
    static UnityDivine FromJson(const nlohmann::json& j);
};

struct GraceDivine {
    std::string graceId;
    std::string name;
    float grace;           // 0.0 to 1.0
    float divinity;        // 0.0 to 1.0
    float mercy;       // 0.0 to 1.0
    float blessing;    // 0.0 to 1.0
    int64_t createdAt;
    
    nlohmann::json ToJson() const;
    static GraceDivine FromJson(const nlohmann::json& j);
};

struct LightDivine {
    std::string lightId;
    std::string name;
    float light;           // 0.0 to 1.0
    float divinity;        // 0.0 to 1.0
    float radiance;    // 0.0 to 1.0
    float illumination; // 0.0 to 1.0
    bool isIlluminated;
    int64_t createdAt;
    
    nlohmann::json ToJson() const;
    static LightDivine FromJson(const nlohmann::json& j);
};

struct TruthDivine {
    std::string truthId;
    std::string name;
    float truth;           // 0.0 to 1.0
    float divinity;        // 0.0 to 1.0
    float veracity;    // 0.0 to 1.0
    float wisdom;      // 0.0 to 1.0
    int64_t createdAt;
    
    nlohmann::json ToJson() const;
    static TruthDivine FromJson(const nlohmann::json& j);
};

// Core engine class
class DivineUnityEngine {
public:
    // Initialization
    static void Init();
    static void Shutdown();
    static bool IsInitialized();
    
    // Divine Unity Structure operations
    static std::string CreateDivineUnityStructure(const std::string& name);
    static bool DestroyDivineUnityStructure(const std::string& divineId);
    static std::shared_ptr<DivineUnityStructure> GetDivineUnityStructure(const std::string& divineId);
    static std::vector<DivineUnityStructure> GetAllDivineUnityStructures();
    static bool ElevateDivinity(const std::string& divineId, float amount);
    static bool ExpandUnity(const std::string& divineId, float amount);
    static bool BestowGrace(const std::string& divineId, float amount);
    static bool ShineLight(const std::string& divineId, float amount);
    static bool RevealTruth(const std::string& divineId, float amount);
    
    // Unity Divine operations
    static std::string CreateUnityDivine(const std::string& name);
    static bool DestroyUnityDivine(const std::string& unityId);
    static std::shared_ptr<UnityDivine> GetUnityDivine(const std::string& unityId);
    static std::vector<UnityDivine> GetAllUnityDivines();
    static bool StrengthenCohesion(const std::string& unityId, float amount);
    static bool CultivateHarmony(const std::string& unityId, float amount);
    static bool DeclareUnified(const std::string& unityId);
    
    // Grace Divine operations
    static std::string CreateGraceDivine(const std::string& name);
    static bool DestroyGraceDivine(const std::string& graceId);
    static std::shared_ptr<GraceDivine> GetGraceDivine(const std::string& graceId);
    static std::vector<GraceDivine> GetAllGraceDivines();
    static bool ExtendMercy(const std::string& graceId, float amount);
    static bool GrantBlessing(const std::string& graceId, float amount);
    
    // Light Divine operations
    static std::string CreateLightDivine(const std::string& name);
    static bool DestroyLightDivine(const std::string& lightId);
    static std::shared_ptr<LightDivine> GetLightDivine(const std::string& lightId);
    static std::vector<LightDivine> GetAllLightDivines();
    static bool AmplifyRadiance(const std::string& lightId, float amount);
    static bool ExpandIllumination(const std::string& lightId, float amount);
    static bool DeclareIlluminated(const std::string& lightId);
    
    // Truth Divine operations
    static std::string CreateTruthDivine(const std::string& name);
    static bool DestroyTruthDivine(const std::string& truthId);
    static std::shared_ptr<TruthDivine> GetTruthDivine(const std::string& truthId);
    static std::vector<TruthDivine> GetAllTruthDivines();
    static bool EnhanceVeracity(const std::string& truthId, float amount);
    static bool ImpartWisdom(const std::string& truthId, float amount);
    
    // Metrics and reporting
    static nlohmann::json GetDivineUnityMetrics();
    static nlohmann::json GenerateDivineUnityReport();
    
private:
    static bool s_initialized;
    static std::mutex s_divineMutex;
    static std::mutex s_unityMutex;
    static std::mutex s_graceMutex;
    static std::mutex s_lightMutex;
    static std::mutex s_truthMutex;
    
    static std::vector<std::shared_ptr<DivineUnityStructure>> s_divineStructures;
    static std::vector<std::shared_ptr<UnityDivine>> s_unityDivines;
    static std::vector<std::shared_ptr<GraceDivine>> s_graceDivines;
    static std::vector<std::shared_ptr<LightDivine>> s_lightDivines;
    static std::vector<std::shared_ptr<TruthDivine>> s_truthDivines;
    
    static std::atomic<int64_t> s_divineCounter;
    static std::atomic<int64_t> s_unityCounter;
    static std::atomic<int64_t> s_graceCounter;
    static std::atomic<int64_t> s_lightCounter;
    static std::atomic<int64_t> s_truthCounter;
};

} // namespace DivineUnity
