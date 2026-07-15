#pragma once

#include <cstring>
#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <atomic>
#include <functional>
#include <nlohmann/json.hpp>

namespace CosmicInfinity {

// Forward declarations
class CosmicInfinityEngine;

// Event callback type
using CosmicEventCallback = std::function<void(const std::string& eventType, const nlohmann::json& data)>;

// Cosmic Infinity Structure - Core entity
struct CosmicInfinityStructure {
    std::string cosmicId;
    std::string name;
    std::string description;
    
    // Cosmic attributes (0.0 - 1.0)
    float cosmicInfinity;     // Degree of cosmic infinity
    float vastness;           // Degree of vastness
    float eternity;           // Degree of eternity
    float immensity;          // Degree of immensity
    float boundlessness;      // Degree of boundlessness
    float endlessness;        // Degree of endlessness
    
    // Metadata
    std::string createdAt;
    std::string updatedAt;
    bool isActive;
    bool isCosmicInfinite;    // Whether achieved cosmic infinite state
    
    CosmicInfinityStructure();
    nlohmann::json ToJson() const;
    static CosmicInfinityStructure FromJson(const nlohmann::json& json);
};

// Vastness Absolute - Represents cosmic vastness
struct VastnessAbsolute {
    std::string vastnessId;
    std::string name;
    std::string description;
    
    float vastness;           // Degree of vastness
    float magnitude;          // Degree of magnitude
    float scope;              // Degree of scope
    
    bool isVast;              // Whether declared vast
    
    std::string createdAt;
    std::string updatedAt;
    
    VastnessAbsolute();
    nlohmann::json ToJson() const;
    static VastnessAbsolute FromJson(const nlohmann::json& json);
};

// Eternity Absolute - Represents cosmic eternity
struct EternityAbsolute {
    std::string eternityId;
    std::string name;
    std::string description;
    
    float eternity;           // Degree of eternity
    float timelessness;       // Degree of timelessness
    float perpetuity;         // Degree of perpetuity
    
    bool isEternal;           // Whether declared eternal
    
    std::string createdAt;
    std::string updatedAt;
    
    EternityAbsolute();
    nlohmann::json ToJson() const;
    static EternityAbsolute FromJson(const nlohmann::json& json);
};

// Immensity Absolute - Represents cosmic immensity
struct ImmensityAbsolute {
    std::string immensityId;
    std::string name;
    std::string description;
    
    float immensity;          // Degree of immensity
    float enormity;             // Degree of enormity
    float hugeness;             // Degree of hugeness
    
    bool isImmense;           // Whether declared immense
    
    std::string createdAt;
    std::string updatedAt;
    
    ImmensityAbsolute();
    nlohmann::json ToJson() const;
    static ImmensityAbsolute FromJson(const nlohmann::json& json);
};

// Boundlessness Absolute - Represents cosmic boundlessness
struct BoundlessnessAbsolute {
    std::string boundlessnessId;
    std::string name;
    std::string description;
    
    float boundlessness;      // Degree of boundlessness
    float limitlessness;      // Degree of limitlessness
    float infinity;           // Degree of infinity
    
    bool isBoundless;         // Whether declared boundless
    
    std::string createdAt;
    std::string updatedAt;
    
    BoundlessnessAbsolute();
    nlohmann::json ToJson() const;
    static BoundlessnessAbsolute FromJson(const nlohmann::json& json);
};

// Endlessness Absolute - Represents cosmic endlessness
struct EndlessnessAbsolute {
    std::string endlessnessId;
    std::string name;
    std::string description;
    
    float endlessness;        // Degree of endlessness
    float ceaselessness;      // Degree of ceaselessness
    float continuity;         // Degree of continuity
    
    bool isEndless;           // Whether declared endless
    
    std::string createdAt;
    std::string updatedAt;
    
    EndlessnessAbsolute();
    nlohmann::json ToJson() const;
    static EndlessnessAbsolute FromJson(const nlohmann::json& json);
};

// Main engine class
class CosmicInfinityEngine {
public:
    // Initialization
    static bool Init();
    static void Shutdown();
    static bool IsInitialized();
    
    // Cosmic Infinity Structure operations
    static std::string CreateCosmicInfinityStructure(const std::string& name);
    static bool DestroyCosmicInfinityStructure(const std::string& cosmicId);
    static std::shared_ptr<CosmicInfinityStructure> GetCosmicInfinityStructure(const std::string& cosmicId);
    static std::vector<CosmicInfinityStructure> GetAllCosmicInfinityStructures();
    static bool UpdateCosmicInfinityStructure(const std::string& cosmicId, const CosmicInfinityStructure& structure);
    
    // Vastness Absolute operations
    static std::string CreateVastnessAbsolute(const std::string& name);
    static bool DestroyVastnessAbsolute(const std::string& vastnessId);
    static std::shared_ptr<VastnessAbsolute> GetVastnessAbsolute(const std::string& vastnessId);
    static std::vector<VastnessAbsolute> GetAllVastnessAbsolutes();
    
    // Eternity Absolute operations
    static std::string CreateEternityAbsolute(const std::string& name);
    static bool DestroyEternityAbsolute(const std::string& eternityId);
    static std::shared_ptr<EternityAbsolute> GetEternityAbsolute(const std::string& eternityId);
    static std::vector<EternityAbsolute> GetAllEternityAbsolutes();
    
    // Immensity Absolute operations
    static std::string CreateImmensityAbsolute(const std::string& name);
    static bool DestroyImmensityAbsolute(const std::string& immensityId);
    static std::shared_ptr<ImmensityAbsolute> GetImmensityAbsolute(const std::string& immensityId);
    static std::vector<ImmensityAbsolute> GetAllImmensityAbsolutes();
    
    // Boundlessness Absolute operations
    static std::string CreateBoundlessnessAbsolute(const std::string& name);
    static bool DestroyBoundlessnessAbsolute(const std::string& boundlessnessId);
    static std::shared_ptr<BoundlessnessAbsolute> GetBoundlessnessAbsolute(const std::string& boundlessnessId);
    static std::vector<BoundlessnessAbsolute> GetAllBoundlessnessAbsolutes();
    
    // Endlessness Absolute operations
    static std::string CreateEndlessnessAbsolute(const std::string& name);
    static bool DestroyEndlessnessAbsolute(const std::string& endlessnessId);
    static std::shared_ptr<EndlessnessAbsolute> GetEndlessnessAbsolute(const std::string& endlessnessId);
    static std::vector<EndlessnessAbsolute> GetAllEndlessnessAbsolutes();
    
    // Cosmic operations
    static bool ExpandCosmicInfinity(const std::string& cosmicId, float amount);
    static bool AmplifyVastness(const std::string& cosmicId, float amount);
    static bool ExtendEternity(const std::string& cosmicId, float amount);
    static bool MagnifyImmensity(const std::string& cosmicId, float amount);
    static bool UnbindBoundlessness(const std::string& cosmicId, float amount);
    static bool PerpetuateEndlessness(const std::string& cosmicId, float amount);
    
    // Vastness operations
    static bool IncreaseMagnitude(const std::string& vastnessId, float amount);
    static bool BroadenScope(const std::string& vastnessId, float amount);
    static bool DeclareVast(const std::string& vastnessId);
    
    // Eternity operations
    static bool AchieveTimelessness(const std::string& eternityId, float amount);
    static bool EnsurePerpetuity(const std::string& eternityId, float amount);
    static bool DeclareEternal(const std::string& eternityId);
    
    // Immensity operations
    static bool ExpandEnormity(const std::string& immensityId, float amount);
    static bool GrowHugeness(const std::string& immensityId, float amount);
    static bool DeclareImmense(const std::string& immensityId);
    
    // Boundlessness operations
    static bool RemoveLimits(const std::string& boundlessnessId, float amount);
    static bool ExpandInfinity(const std::string& boundlessnessId, float amount);
    static bool DeclareBoundless(const std::string& boundlessnessId);
    
    // Endlessness operations
    static bool MaintainCeaselessness(const std::string& endlessnessId, float amount);
    static bool EnsureContinuity(const std::string& endlessnessId, float amount);
    static bool DeclareEndless(const std::string& endlessnessId);
    
    // Metrics
    static nlohmann::json GetCosmicInfinityMetrics();
    
    // Event system
    static void RegisterEventCallback(CosmicEventCallback callback);
    static void UnregisterEventCallback(CosmicEventCallback callback);
    
private:
    static std::atomic<bool> s_initialized;
    static std::mutex s_cosmicMutex;
    static std::mutex s_vastnessMutex;
    static std::mutex s_eternityMutex;
    static std::mutex s_immensityMutex;
    static std::mutex s_boundlessnessMutex;
    static std::mutex s_endlessnessMutex;
    static std::mutex s_callbackMutex;
    
    static std::map<std::string, CosmicInfinityStructure> s_cosmicStructures;
    static std::map<std::string, VastnessAbsolute> s_vastnessAbsolutes;
    static std::map<std::string, EternityAbsolute> s_eternityAbsolutes;
    static std::map<std::string, ImmensityAbsolute> s_immensityAbsolutes;
    static std::map<std::string, BoundlessnessAbsolute> s_boundlessnessAbsolutes;
    static std::map<std::string, EndlessnessAbsolute> s_endlessnessAbsolutes;
    static std::vector<CosmicEventCallback> s_eventCallbacks;
    
    static void EmitEvent(const std::string& eventType, const nlohmann::json& data);
    static std::string GenerateId();
    static std::string GetCurrentTimestamp();
};

} // namespace CosmicInfinity
