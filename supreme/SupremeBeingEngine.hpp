#pragma once

#include <cstring>
#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <atomic>
#include <nlohmann/json.hpp>

namespace SupremeBeing {

// Forward declarations
struct SupremeBeingStructure;
struct BeingSupreme;
struct EssenceSupreme;
struct NatureSupreme;
struct SpiritSupreme;
struct WillSupreme;

// Core structure representing supreme being
struct SupremeBeingStructure {
    std::string supremeId;
    std::string name;
    std::string description;
    
    // Core supreme metrics (0.0 - 1.0)
    float supremeness;       // Degree of supremeness
    float being;             // Level of being
    float essence;           // Depth of essence
    float nature;            // Clarity of nature
    float spirit;            // Purity of spirit
    float will;              // State of will
    
    // Timestamps
    std::string createdAt;
    std::string updatedAt;
    
    // Status
    bool isActive;
    bool isSupreme;
    
    SupremeBeingStructure();
    
    nlohmann::json ToJson() const;
    static SupremeBeingStructure FromJson(const nlohmann::json& json);
};

// Being supreme - ultimate being
struct BeingSupreme {
    std::string beingId;
    std::string name;
    std::string description;
    
    float being;
    float existence;
    float presence;
    
    bool isBeing;
    
    std::string createdAt;
    std::string updatedAt;
    
    BeingSupreme();
    
    nlohmann::json ToJson() const;
    static BeingSupreme FromJson(const nlohmann::json& json);
};

// Essence supreme - ultimate essence
struct EssenceSupreme {
    std::string essenceId;
    std::string name;
    std::string description;
    
    float essence;
    float substance;
    float core;
    
    bool isEssence;
    
    std::string createdAt;
    std::string updatedAt;
    
    EssenceSupreme();
    
    nlohmann::json ToJson() const;
    static EssenceSupreme FromJson(const nlohmann::json& json);
};

// Nature supreme - ultimate nature
struct NatureSupreme {
    std::string natureId;
    std::string name;
    std::string description;
    
    float nature;
    float character;
    float quality;
    
    bool isNatural;
    
    std::string createdAt;
    std::string updatedAt;
    
    NatureSupreme();
    
    nlohmann::json ToJson() const;
    static NatureSupreme FromJson(const nlohmann::json& json);
};

// Spirit supreme - ultimate spirit
struct SpiritSupreme {
    std::string spiritId;
    std::string name;
    std::string description;
    
    float spirit;
    float soul;
    float consciousness;
    
    bool isSpiritual;
    
    std::string createdAt;
    std::string updatedAt;
    
    SpiritSupreme();
    
    nlohmann::json ToJson() const;
    static SpiritSupreme FromJson(const nlohmann::json& json);
};

// Will supreme - ultimate will
struct WillSupreme {
    std::string willId;
    std::string name;
    std::string description;
    
    float will;
    float determination;
    float resolve;
    
    bool isWilling;
    
    std::string createdAt;
    std::string updatedAt;
    
    WillSupreme();
    
    nlohmann::json ToJson() const;
    static WillSupreme FromJson(const nlohmann::json& json);
};

// Main engine class
class SupremeBeingEngine {
public:
    // Initialization
    static bool Init();
    static void Shutdown();
    static bool IsInitialized();
    
    // Supreme being structure operations
    static std::string CreateSupremeBeingStructure(const std::string& name);
    static bool DestroySupremeBeingStructure(const std::string& supremeId);
    static std::shared_ptr<SupremeBeingStructure> GetSupremeBeingStructure(const std::string& supremeId);
    static std::vector<SupremeBeingStructure> GetAllSupremeBeingStructures();
    static bool UpdateSupremeBeingStructure(const std::string& supremeId, const SupremeBeingStructure& structure);
    
    // Being supreme operations
    static std::string CreateBeingSupreme(const std::string& name);
    static bool DestroyBeingSupreme(const std::string& beingId);
    static std::shared_ptr<BeingSupreme> GetBeingSupreme(const std::string& beingId);
    static std::vector<BeingSupreme> GetAllBeingSupremes();
    
    // Essence supreme operations
    static std::string CreateEssenceSupreme(const std::string& name);
    static bool DestroyEssenceSupreme(const std::string& essenceId);
    static std::shared_ptr<EssenceSupreme> GetEssenceSupreme(const std::string& essenceId);
    static std::vector<EssenceSupreme> GetAllEssenceSupremes();
    
    // Nature supreme operations
    static std::string CreateNatureSupreme(const std::string& name);
    static bool DestroyNatureSupreme(const std::string& natureId);
    static std::shared_ptr<NatureSupreme> GetNatureSupreme(const std::string& natureId);
    static std::vector<NatureSupreme> GetAllNatureSupremes();
    
    // Spirit supreme operations
    static std::string CreateSpiritSupreme(const std::string& name);
    static bool DestroySpiritSupreme(const std::string& spiritId);
    static std::shared_ptr<SpiritSupreme> GetSpiritSupreme(const std::string& spiritId);
    static std::vector<SpiritSupreme> GetAllSpiritSupremes();
    
    // Will supreme operations
    static std::string CreateWillSupreme(const std::string& name);
    static bool DestroyWillSupreme(const std::string& willId);
    static std::shared_ptr<WillSupreme> GetWillSupreme(const std::string& willId);
    static std::vector<WillSupreme> GetAllWillSupremes();
    
    // Supreme operations
    static bool ExpandSupremeness(const std::string& supremeId, float amount);
    static bool DeepenBeing(const std::string& supremeId, float amount);
    static bool CultivateEssence(const std::string& supremeId, float amount);
    static bool RefineNature(const std::string& supremeId, float amount);
    static bool ElevateSpirit(const std::string& supremeId, float amount);
    static bool StrengthenWill(const std::string& supremeId, float amount);
    
    // Being operations
    static bool AffirmExistence(const std::string& beingId, float amount);
    static bool ManifestPresence(const std::string& beingId, float amount);
    static bool DeclareBeing(const std::string& beingId);
    
    // Essence operations
    static bool DeepenSubstance(const std::string& essenceId, float amount);
    static bool StrengthenCore(const std::string& essenceId, float amount);
    static bool DeclareEssence(const std::string& essenceId);
    
    // Nature operations
    static bool DevelopCharacter(const std::string& natureId, float amount);
    static bool EnhanceQuality(const std::string& natureId, float amount);
    static bool DeclareNatural(const std::string& natureId);
    
    // Spirit operations
    static bool NurtureSoul(const std::string& spiritId, float amount);
    static bool ExpandConsciousness(const std::string& spiritId, float amount);
    static bool DeclareSpiritual(const std::string& spiritId);
    
    // Will operations
    static bool FortifyDetermination(const std::string& willId, float amount);
    static bool CementResolve(const std::string& willId, float amount);
    static bool DeclareWilling(const std::string& willId);
    
    // Metrics
    static nlohmann::json GetSupremeBeingMetrics();
    
    // Event callbacks
    using SupremeBeingEventCallback = std::function<void(const std::string& eventType, const nlohmann::json& data)>;
    static void RegisterEventCallback(SupremeBeingEventCallback callback);
    static void UnregisterEventCallback(SupremeBeingEventCallback callback);
    
private:
    static std::atomic<bool> s_initialized;
    static std::mutex s_supremeMutex;
    static std::mutex s_beingMutex;
    static std::mutex s_essenceMutex;
    static std::mutex s_natureMutex;
    static std::mutex s_spiritMutex;
    static std::mutex s_willMutex;
    static std::mutex s_callbackMutex;
    
    static std::map<std::string, SupremeBeingStructure> s_supremeStructures;
    static std::map<std::string, BeingSupreme> s_beingSupremes;
    static std::map<std::string, EssenceSupreme> s_essenceSupremes;
    static std::map<std::string, NatureSupreme> s_natureSupremes;
    static std::map<std::string, SpiritSupreme> s_spiritSupremes;
    static std::map<std::string, WillSupreme> s_willSupremes;
    static std::vector<SupremeBeingEventCallback> s_eventCallbacks;
    
    static void EmitEvent(const std::string& eventType, const nlohmann::json& data);
    static std::string GenerateId();
    static std::string GetCurrentTimestamp();
};

} // namespace SupremeBeing
