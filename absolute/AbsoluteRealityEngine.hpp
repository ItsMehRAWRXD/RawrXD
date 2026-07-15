#pragma once

#include <cstring>
#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <atomic>
#include <nlohmann/json.hpp>

namespace AbsoluteReality {

// Forward declarations
struct AbsoluteRealityStructure;
struct RealityAbsolute;
struct TruthAbsolute;
struct ExistenceAbsolute;
struct ActualityAbsolute;
struct SubstanceAbsolute;

// Core structure representing absolute reality
struct AbsoluteRealityStructure {
    std::string absoluteId;
    std::string name;
    std::string description;
    
    // Core absolute metrics (0.0 - 1.0)
    float absoluteness;      // Degree of absoluteness
    float reality;           // Level of reality
    float truth;             // Depth of truth
    float existence;         // Clarity of existence
    float actuality;         // Purity of actuality
    float substance;         // State of substance
    
    // Timestamps
    std::string createdAt;
    std::string updatedAt;
    
    // Status
    bool isActive;
    bool isAbsolute;
    
    AbsoluteRealityStructure();
    
    nlohmann::json ToJson() const;
    static AbsoluteRealityStructure FromJson(const nlohmann::json& json);
};

// Reality absolute - ultimate reality
struct RealityAbsolute {
    std::string realityId;
    std::string name;
    std::string description;
    
    float reality;
    float actuality;
    float existence;
    
    bool isReal;
    
    std::string createdAt;
    std::string updatedAt;
    
    RealityAbsolute();
    
    nlohmann::json ToJson() const;
    static RealityAbsolute FromJson(const nlohmann::json& json);
};

// Truth absolute - ultimate truth
struct TruthAbsolute {
    std::string truthId;
    std::string name;
    std::string description;
    
    float truth;
    float veracity;
    float validity;
    
    bool isTrue;
    
    std::string createdAt;
    std::string updatedAt;
    
    TruthAbsolute();
    
    nlohmann::json ToJson() const;
    static TruthAbsolute FromJson(const nlohmann::json& json);
};

// Existence absolute - ultimate existence
struct ExistenceAbsolute {
    std::string existenceId;
    std::string name;
    std::string description;
    
    float existence;
    float being;
    float presence;
    
    bool isExisting;
    
    std::string createdAt;
    std::string updatedAt;
    
    ExistenceAbsolute();
    
    nlohmann::json ToJson() const;
    static ExistenceAbsolute FromJson(const nlohmann::json& json);
};

// Actuality absolute - ultimate actuality
struct ActualityAbsolute {
    std::string actualityId;
    std::string name;
    std::string description;
    
    float actuality;
    float factuality;
    float certainty;
    
    bool isActual;
    
    std::string createdAt;
    std::string updatedAt;
    
    ActualityAbsolute();
    
    nlohmann::json ToJson() const;
    static ActualityAbsolute FromJson(const nlohmann::json& json);
};

// Substance absolute - ultimate substance
struct SubstanceAbsolute {
    std::string substanceId;
    std::string name;
    std::string description;
    
    float substance;
    float essence;
    float matter;
    
    bool isSubstantial;
    
    std::string createdAt;
    std::string updatedAt;
    
    SubstanceAbsolute();
    
    nlohmann::json ToJson() const;
    static SubstanceAbsolute FromJson(const nlohmann::json& json);
};

// Main engine class
class AbsoluteRealityEngine {
public:
    // Initialization
    static bool Init();
    static void Shutdown();
    static bool IsInitialized();
    
    // Absolute reality structure operations
    static std::string CreateAbsoluteRealityStructure(const std::string& name);
    static bool DestroyAbsoluteRealityStructure(const std::string& absoluteId);
    static std::shared_ptr<AbsoluteRealityStructure> GetAbsoluteRealityStructure(const std::string& absoluteId);
    static std::vector<AbsoluteRealityStructure> GetAllAbsoluteRealityStructures();
    static bool UpdateAbsoluteRealityStructure(const std::string& absoluteId, const AbsoluteRealityStructure& structure);
    
    // Reality absolute operations
    static std::string CreateRealityAbsolute(const std::string& name);
    static bool DestroyRealityAbsolute(const std::string& realityId);
    static std::shared_ptr<RealityAbsolute> GetRealityAbsolute(const std::string& realityId);
    static std::vector<RealityAbsolute> GetAllRealityAbsolutes();
    
    // Truth absolute operations
    static std::string CreateTruthAbsolute(const std::string& name);
    static bool DestroyTruthAbsolute(const std::string& truthId);
    static std::shared_ptr<TruthAbsolute> GetTruthAbsolute(const std::string& truthId);
    static std::vector<TruthAbsolute> GetAllTruthAbsolutes();
    
    // Existence absolute operations
    static std::string CreateExistenceAbsolute(const std::string& name);
    static bool DestroyExistenceAbsolute(const std::string& existenceId);
    static std::shared_ptr<ExistenceAbsolute> GetExistenceAbsolute(const std::string& existenceId);
    static std::vector<ExistenceAbsolute> GetAllExistenceAbsolutes();
    
    // Actuality absolute operations
    static std::string CreateActualityAbsolute(const std::string& name);
    static bool DestroyActualityAbsolute(const std::string& actualityId);
    static std::shared_ptr<ActualityAbsolute> GetActualityAbsolute(const std::string& actualityId);
    static std::vector<ActualityAbsolute> GetAllActualityAbsolutes();
    
    // Substance absolute operations
    static std::string CreateSubstanceAbsolute(const std::string& name);
    static bool DestroySubstanceAbsolute(const std::string& substanceId);
    static std::shared_ptr<SubstanceAbsolute> GetSubstanceAbsolute(const std::string& substanceId);
    static std::vector<SubstanceAbsolute> GetAllSubstanceAbsolutes();
    
    // Absolute operations
    static bool ExpandAbsoluteness(const std::string& absoluteId, float amount);
    static bool DeepenReality(const std::string& absoluteId, float amount);
    static bool RevealTruth(const std::string& absoluteId, float amount);
    static bool AffirmExistence(const std::string& absoluteId, float amount);
    static bool ManifestActuality(const std::string& absoluteId, float amount);
    static bool SolidifySubstance(const std::string& absoluteId, float amount);
    
    // Reality operations
    static bool RealizeActuality(const std::string& realityId, float amount);
    static bool ConfirmExistence(const std::string& realityId, float amount);
    static bool DeclareReal(const std::string& realityId);
    
    // Truth operations
    static bool VerifyVeracity(const std::string& truthId, float amount);
    static bool ValidateTruth(const std::string& truthId, float amount);
    static bool DeclareTrue(const std::string& truthId);
    
    // Existence operations
    static bool AffirmBeing(const std::string& existenceId, float amount);
    static bool ManifestPresence(const std::string& existenceId, float amount);
    static bool DeclareExisting(const std::string& existenceId);
    
    // Actuality operations
    static bool EstablishFactuality(const std::string& actualityId, float amount);
    static bool EnsureCertainty(const std::string& actualityId, float amount);
    static bool DeclareActual(const std::string& actualityId);
    
    // Substance operations
    static bool DeepenEssence(const std::string& substanceId, float amount);
    static bool MaterializeMatter(const std::string& substanceId, float amount);
    static bool DeclareSubstantial(const std::string& substanceId);
    
    // Metrics
    static nlohmann::json GetAbsoluteRealityMetrics();
    
    // Event callbacks
    using AbsoluteRealityEventCallback = std::function<void(const std::string& eventType, const nlohmann::json& data)>;
    static void RegisterEventCallback(AbsoluteRealityEventCallback callback);
    static void UnregisterEventCallback(AbsoluteRealityEventCallback callback);
    
private:
    static std::atomic<bool> s_initialized;
    static std::mutex s_absoluteMutex;
    static std::mutex s_realityMutex;
    static std::mutex s_truthMutex;
    static std::mutex s_existenceMutex;
    static std::mutex s_actualityMutex;
    static std::mutex s_substanceMutex;
    static std::mutex s_callbackMutex;
    
    static std::map<std::string, AbsoluteRealityStructure> s_absoluteStructures;
    static std::map<std::string, RealityAbsolute> s_realityAbsolutes;
    static std::map<std::string, TruthAbsolute> s_truthAbsolutes;
    static std::map<std::string, ExistenceAbsolute> s_existenceAbsolutes;
    static std::map<std::string, ActualityAbsolute> s_actualityAbsolutes;
    static std::map<std::string, SubstanceAbsolute> s_substanceAbsolutes;
    static std::vector<AbsoluteRealityEventCallback> s_eventCallbacks;
    
    static void EmitEvent(const std::string& eventType, const nlohmann::json& data);
    static std::string GenerateId();
    static std::string GetCurrentTimestamp();
};

} // namespace AbsoluteReality
