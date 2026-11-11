#pragma once

#include <cstring>
#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <atomic>
#include <functional>
#include <nlohmann/json.hpp>

namespace EternalVoid {

// Forward declarations
class EternalVoidEngine;

// Event callback type
using EternalEventCallback = std::function<void(const std::string& eventType, const nlohmann::json& data)>;

// Eternal Void Structure - Core entity
struct EternalVoidStructure {
    std::string eternalId;
    std::string name;
    std::string description;
    
    // Eternal attributes (0.0 - 1.0)
    float eternalVoid;        // Degree of eternal void
    float emptiness;          // Degree of emptiness
    float nothingness;        // Degree of nothingness
    float silence;            // Degree of silence
    float stillness;          // Degree of stillness
    float darkness;           // Degree of darkness
    
    // Metadata
    std::string createdAt;
    std::string updatedAt;
    bool isActive;
    bool isEternalVoid;       // Whether achieved eternal void state
    
    EternalVoidStructure();
    nlohmann::json ToJson() const;
    static EternalVoidStructure FromJson(const nlohmann::json& json);
};

// Emptiness Absolute - Represents eternal emptiness
struct EmptinessAbsolute {
    std::string emptinessId;
    std::string name;
    std::string description;
    
    float emptiness;          // Degree of emptiness
    float vacancy;            // Degree of vacancy
    float hollowness;         // Degree of hollowness
    
    bool isEmpty;             // Whether declared empty
    
    std::string createdAt;
    std::string updatedAt;
    
    EmptinessAbsolute();
    nlohmann::json ToJson() const;
    static EmptinessAbsolute FromJson(const nlohmann::json& json);
};

// Nothingness Absolute - Represents eternal nothingness
struct NothingnessAbsolute {
    std::string nothingnessId;
    std::string name;
    std::string description;
    
    float nothingness;        // Degree of nothingness
    float nullity;            // Degree of nullity
    float voidness;           // Degree of voidness
    
    bool isNothing;           // Whether declared nothing
    
    std::string createdAt;
    std::string updatedAt;
    
    NothingnessAbsolute();
    nlohmann::json ToJson() const;
    static NothingnessAbsolute FromJson(const nlohmann::json& json);
};

// Silence Absolute - Represents eternal silence
struct SilenceAbsolute {
    std::string silenceId;
    std::string name;
    std::string description;
    
    float silence;            // Degree of silence
    float quietude;           // Degree of quietude
    float muteness;           // Degree of muteness
    
    bool isSilent;            // Whether declared silent
    
    std::string createdAt;
    std::string updatedAt;
    
    SilenceAbsolute();
    nlohmann::json ToJson() const;
    static SilenceAbsolute FromJson(const nlohmann::json& json);
};

// Stillness Absolute - Represents eternal stillness
struct StillnessAbsolute {
    std::string stillnessId;
    std::string name;
    std::string description;
    
    float stillness;          // Degree of stillness
    float motionlessness;     // Degree of motionlessness
    float calmness;           // Degree of calmness
    
    bool isStill;             // Whether declared still
    
    std::string createdAt;
    std::string updatedAt;
    
    StillnessAbsolute();
    nlohmann::json ToJson() const;
    static StillnessAbsolute FromJson(const nlohmann::json& json);
};

// Darkness Absolute - Represents eternal darkness
struct DarknessAbsolute {
    std::string darknessId;
    std::string name;
    std::string description;
    
    float darkness;           // Degree of darkness
    float obscurity;          // Degree of obscurity
    float shadow;             // Degree of shadow
    
    bool isDark;              // Whether declared dark
    
    std::string createdAt;
    std::string updatedAt;
    
    DarknessAbsolute();
    nlohmann::json ToJson() const;
    static DarknessAbsolute FromJson(const nlohmann::json& json);
};

// Main engine class
class EternalVoidEngine {
public:
    // Initialization
    static bool Init();
    static void Shutdown();
    static bool IsInitialized();
    
    // Eternal Void Structure operations
    static std::string CreateEternalVoidStructure(const std::string& name);
    static bool DestroyEternalVoidStructure(const std::string& eternalId);
    static std::shared_ptr<EternalVoidStructure> GetEternalVoidStructure(const std::string& eternalId);
    static std::vector<EternalVoidStructure> GetAllEternalVoidStructures();
    static bool UpdateEternalVoidStructure(const std::string& eternalId, const EternalVoidStructure& structure);
    
    // Emptiness Absolute operations
    static std::string CreateEmptinessAbsolute(const std::string& name);
    static bool DestroyEmptinessAbsolute(const std::string& emptinessId);
    static std::shared_ptr<EmptinessAbsolute> GetEmptinessAbsolute(const std::string& emptinessId);
    static std::vector<EmptinessAbsolute> GetAllEmptinessAbsolutes();
    
    // Nothingness Absolute operations
    static std::string CreateNothingnessAbsolute(const std::string& name);
    static bool DestroyNothingnessAbsolute(const std::string& nothingnessId);
    static std::shared_ptr<NothingnessAbsolute> GetNothingnessAbsolute(const std::string& nothingnessId);
    static std::vector<NothingnessAbsolute> GetAllNothingnessAbsolutes();
    
    // Silence Absolute operations
    static std::string CreateSilenceAbsolute(const std::string& name);
    static bool DestroySilenceAbsolute(const std::string& silenceId);
    static std::shared_ptr<SilenceAbsolute> GetSilenceAbsolute(const std::string& silenceId);
    static std::vector<SilenceAbsolute> GetAllSilenceAbsolutes();
    
    // Stillness Absolute operations
    static std::string CreateStillnessAbsolute(const std::string& name);
    static bool DestroyStillnessAbsolute(const std::string& stillnessId);
    static std::shared_ptr<StillnessAbsolute> GetStillnessAbsolute(const std::string& stillnessId);
    static std::vector<StillnessAbsolute> GetAllStillnessAbsolutes();
    
    // Darkness Absolute operations
    static std::string CreateDarknessAbsolute(const std::string& name);
    static bool DestroyDarknessAbsolute(const std::string& darknessId);
    static std::shared_ptr<DarknessAbsolute> GetDarknessAbsolute(const std::string& darknessId);
    static std::vector<DarknessAbsolute> GetAllDarknessAbsolutes();
    
    // Eternal operations
    static bool DeepenEternalVoid(const std::string& eternalId, float amount);
    static bool EmbraceEmptiness(const std::string& eternalId, float amount);
    static bool AcceptNothingness(const std::string& eternalId, float amount);
    static bool EnterSilence(const std::string& eternalId, float amount);
    static bool AchieveStillness(const std::string& eternalId, float amount);
    static bool DescendIntoDarkness(const std::string& eternalId, float amount);
    
    // Emptiness operations
    static bool CreateVacancy(const std::string& emptinessId, float amount);
    static bool DeepenHollowness(const std::string& emptinessId, float amount);
    static bool DeclareEmpty(const std::string& emptinessId);
    
    // Nothingness operations
    static bool EmbraceNullity(const std::string& nothingnessId, float amount);
    static bool ExpandVoidness(const std::string& nothingnessId, float amount);
    static bool DeclareNothing(const std::string& nothingnessId);
    
    // Silence operations
    static bool CultivateQuietude(const std::string& silenceId, float amount);
    static bool DeepenMuteness(const std::string& silenceId, float amount);
    static bool DeclareSilent(const std::string& silenceId);
    
    // Stillness operations
    static bool AchieveMotionlessness(const std::string& stillnessId, float amount);
    static bool CultivateCalmness(const std::string& stillnessId, float amount);
    static bool DeclareStill(const std::string& stillnessId);
    
    // Darkness operations
    static bool DeepenObscurity(const std::string& darknessId, float amount);
    static bool ExtendShadow(const std::string& darknessId, float amount);
    static bool DeclareDark(const std::string& darknessId);
    
    // Metrics
    static nlohmann::json GetEternalVoidMetrics();
    
    // Event system
    static void RegisterEventCallback(EternalEventCallback callback);
    static void UnregisterEventCallback(EternalEventCallback callback);
    
private:
    static std::atomic<bool> s_initialized;
    static std::mutex s_eternalMutex;
    static std::mutex s_emptinessMutex;
    static std::mutex s_nothingnessMutex;
    static std::mutex s_silenceMutex;
    static std::mutex s_stillnessMutex;
    static std::mutex s_darknessMutex;
    static std::mutex s_callbackMutex;
    
    static std::map<std::string, EternalVoidStructure> s_eternalStructures;
    static std::map<std::string, EmptinessAbsolute> s_emptinessAbsolutes;
    static std::map<std::string, NothingnessAbsolute> s_nothingnessAbsolutes;
    static std::map<std::string, SilenceAbsolute> s_silenceAbsolutes;
    static std::map<std::string, StillnessAbsolute> s_stillnessAbsolutes;
    static std::map<std::string, DarknessAbsolute> s_darknessAbsolutes;
    static std::vector<EternalEventCallback> s_eventCallbacks;
    
    static void EmitEvent(const std::string& eventType, const nlohmann::json& data);
    static std::string GenerateId();
    static std::string GetCurrentTimestamp();
};

} // namespace EternalVoid
