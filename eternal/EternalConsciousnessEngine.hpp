#pragma once

#include <cstring>
#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <atomic>
#include <nlohmann/json.hpp>

namespace EternalConsciousness {

// Forward declarations
struct EternalConsciousnessStructure;
struct ConsciousnessEternal;
struct AwarenessEternal;
struct PresenceEternal;
struct ExistenceEternal;
struct ContinuityEternal;

// Core structure representing eternal consciousness
struct EternalConsciousnessStructure {
    std::string eternalId;
    std::string name;
    std::string description;
    
    // Core eternal metrics (0.0 - 1.0)
    float eternality;        // Degree of eternality
    float consciousness;     // Level of consciousness
    float awareness;         // Depth of awareness
    float presence;          // State of presence
    float existence;         // Purity of existence
    float continuity;        // Flow of continuity
    
    // Timestamps
    std::string createdAt;
    std::string updatedAt;
    
    // Status
    bool isActive;
    bool isEternal;
    
    EternalConsciousnessStructure();
    
    nlohmann::json ToJson() const;
    static EternalConsciousnessStructure FromJson(const nlohmann::json& json);
};

// Consciousness eternal - timeless consciousness
struct ConsciousnessEternal {
    std::string consciousnessId;
    std::string name;
    std::string description;
    
    float consciousness;
    float perception;
    float cognition;
    
    bool isConscious;
    
    std::string createdAt;
    std::string updatedAt;
    
    ConsciousnessEternal();
    
    nlohmann::json ToJson() const;
    static ConsciousnessEternal FromJson(const nlohmann::json& json);
};

// Awareness eternal - perpetual awareness
struct AwarenessEternal {
    std::string awarenessId;
    std::string name;
    std::string description;
    
    float awareness;
    float mindfulness;
    float attention;
    
    bool isAware;
    
    std::string createdAt;
    std::string updatedAt;
    
    AwarenessEternal();
    
    nlohmann::json ToJson() const;
    static AwarenessEternal FromJson(const nlohmann::json& json);
};

// Presence eternal - timeless presence
struct PresenceEternal {
    std::string presenceId;
    std::string name;
    std::string description;
    
    float presence;
    float immediacy;
    float embodiment;
    
    bool isPresent;
    
    std::string createdAt;
    std::string updatedAt;
    
    PresenceEternal();
    
    nlohmann::json ToJson() const;
    static PresenceEternal FromJson(const nlohmann::json& json);
};

// Existence eternal - perpetual existence
struct ExistenceEternal {
    std::string existenceId;
    std::string name;
    std::string description;
    
    float existence;
    float being;
    float essence;
    
    bool isExisting;
    
    std::string createdAt;
    std::string updatedAt;
    
    ExistenceEternal();
    
    nlohmann::json ToJson() const;
    static ExistenceEternal FromJson(const nlohmann::json& json);
};

// Continuity eternal - eternal flow
struct ContinuityEternal {
    std::string continuityId;
    std::string name;
    std::string description;
    
    float continuity;
    float persistence;
    float endurance;
    
    bool isContinuous;
    
    std::string createdAt;
    std::string updatedAt;
    
    ContinuityEternal();
    
    nlohmann::json ToJson() const;
    static ContinuityEternal FromJson(const nlohmann::json& json);
};

// Main engine class
class EternalConsciousnessEngine {
public:
    // Initialization
    static bool Init();
    static void Shutdown();
    static bool IsInitialized();
    
    // Eternal consciousness structure operations
    static std::string CreateEternalConsciousnessStructure(const std::string& name);
    static bool DestroyEternalConsciousnessStructure(const std::string& eternalId);
    static std::shared_ptr<EternalConsciousnessStructure> GetEternalConsciousnessStructure(const std::string& eternalId);
    static std::vector<EternalConsciousnessStructure> GetAllEternalConsciousnessStructures();
    static bool UpdateEternalConsciousnessStructure(const std::string& eternalId, const EternalConsciousnessStructure& structure);
    
    // Consciousness eternal operations
    static std::string CreateConsciousnessEternal(const std::string& name);
    static bool DestroyConsciousnessEternal(const std::string& consciousnessId);
    static std::shared_ptr<ConsciousnessEternal> GetConsciousnessEternal(const std::string& consciousnessId);
    static std::vector<ConsciousnessEternal> GetAllConsciousnessEternals();
    
    // Awareness eternal operations
    static std::string CreateAwarenessEternal(const std::string& name);
    static bool DestroyAwarenessEternal(const std::string& awarenessId);
    static std::shared_ptr<AwarenessEternal> GetAwarenessEternal(const std::string& awarenessId);
    static std::vector<AwarenessEternal> GetAllAwarenessEternals();
    
    // Presence eternal operations
    static std::string CreatePresenceEternal(const std::string& name);
    static bool DestroyPresenceEternal(const std::string& presenceId);
    static std::shared_ptr<PresenceEternal> GetPresenceEternal(const std::string& presenceId);
    static std::vector<PresenceEternal> GetAllPresenceEternals();
    
    // Existence eternal operations
    static std::string CreateExistenceEternal(const std::string& name);
    static bool DestroyExistenceEternal(const std::string& existenceId);
    static std::shared_ptr<ExistenceEternal> GetExistenceEternal(const std::string& existenceId);
    static std::vector<ExistenceEternal> GetAllExistenceEternals();
    
    // Continuity eternal operations
    static std::string CreateContinuityEternal(const std::string& name);
    static bool DestroyContinuityEternal(const std::string& continuityId);
    static std::shared_ptr<ContinuityEternal> GetContinuityEternal(const std::string& continuityId);
    static std::vector<ContinuityEternal> GetAllContinuityEternals();
    
    // Eternal operations
    static bool ExpandEternality(const std::string& eternalId, float amount);
    static bool DeepenConsciousness(const std::string& eternalId, float amount);
    static bool HeightenAwareness(const std::string& eternalId, float amount);
    static bool ManifestPresence(const std::string& eternalId, float amount);
    static bool AffirmExistence(const std::string& eternalId, float amount);
    static bool MaintainContinuity(const std::string& eternalId, float amount);
    
    // Consciousness operations
    static bool SharpenPerception(const std::string& consciousnessId, float amount);
    static bool EnhanceCognition(const std::string& consciousnessId, float amount);
    static bool DeclareConscious(const std::string& consciousnessId);
    
    // Awareness operations
    static bool CultivateMindfulness(const std::string& awarenessId, float amount);
    static bool FocusAttention(const std::string& awarenessId, float amount);
    static bool DeclareAware(const std::string& awarenessId);
    
    // Presence operations
    static bool DeepenImmediacy(const std::string& presenceId, float amount);
    static bool StrengthenEmbodiment(const std::string& presenceId, float amount);
    static bool DeclarePresent(const std::string& presenceId);
    
    // Existence operations
    static bool AffirmBeing(const std::string& existenceId, float amount);
    static bool RealizeEssence(const std::string& existenceId, float amount);
    static bool DeclareExisting(const std::string& existenceId);
    
    // Continuity operations
    static bool StrengthenPersistence(const std::string& continuityId, float amount);
    static bool BuildEndurance(const std::string& continuityId, float amount);
    static bool DeclareContinuous(const std::string& continuityId);
    
    // Metrics
    static nlohmann::json GetEternalConsciousnessMetrics();
    
    // Event callbacks
    using EternalConsciousnessEventCallback = std::function<void(const std::string& eventType, const nlohmann::json& data)>;
    static void RegisterEventCallback(EternalConsciousnessEventCallback callback);
    static void UnregisterEventCallback(EternalConsciousnessEventCallback callback);
    
private:
    static std::atomic<bool> s_initialized;
    static std::mutex s_eternalMutex;
    static std::mutex s_consciousnessMutex;
    static std::mutex s_awarenessMutex;
    static std::mutex s_presenceMutex;
    static std::mutex s_existenceMutex;
    static std::mutex s_continuityMutex;
    static std::mutex s_callbackMutex;
    
    static std::map<std::string, EternalConsciousnessStructure> s_eternalStructures;
    static std::map<std::string, ConsciousnessEternal> s_consciousnessEternals;
    static std::map<std::string, AwarenessEternal> s_awarenessEternals;
    static std::map<std::string, PresenceEternal> s_presenceEternals;
    static std::map<std::string, ExistenceEternal> s_existenceEternals;
    static std::map<std::string, ContinuityEternal> s_continuityEternals;
    static std::vector<EternalConsciousnessEventCallback> s_eventCallbacks;
    
    static void EmitEvent(const std::string& eventType, const nlohmann::json& data);
    static std::string GenerateId();
    static std::string GetCurrentTimestamp();
};

} // namespace EternalConsciousness
