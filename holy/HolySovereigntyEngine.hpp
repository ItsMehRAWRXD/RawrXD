#pragma once

#include <cstring>
#include <vector>
#include <memory>
#include <mutex>
#include <atomic>
#include <nlohmann/json.hpp>

namespace HolySovereignty {

// Forward declarations
struct HolySovereigntyStructure;
struct SovereigntyHoly;
struct GloryHoly;
struct MajestyHoly;
struct PowerHoly;

// Core data structures
struct HolySovereigntyStructure {
    std::string holyId;
    std::string name;
    float holiness;        // 0.0 to 1.0
    float sovereignty;     // 0.0 to 1.0
    float glory;         // 0.0 to 1.0
    float majesty;       // 0.0 to 1.0
    float power;         // 0.0 to 1.0
    int64_t createdAt;
    int64_t lastModified;
    bool isActive;
    
    nlohmann::json ToJson() const;
    static HolySovereigntyStructure FromJson(const nlohmann::json& j);
};

struct SovereigntyHoly {
    std::string sovereigntyId;
    std::string name;
    float sovereignty;     // 0.0 to 1.0
    float holiness;        // 0.0 to 1.0
    float supremacy;     // 0.0 to 1.0
    float dominion;      // 0.0 to 1.0
    bool isSupreme;
    int64_t createdAt;
    
    nlohmann::json ToJson() const;
    static SovereigntyHoly FromJson(const nlohmann::json& j);
};

struct GloryHoly {
    std::string gloryId;
    std::string name;
    float glory;           // 0.0 to 1.0
    float holiness;        // 0.0 to 1.0
    float brilliance;    // 0.0 to 1.0
    float splendor;      // 0.0 to 1.0
    int64_t createdAt;
    
    nlohmann::json ToJson() const;
    static GloryHoly FromJson(const nlohmann::json& j);
};

struct MajestyHoly {
    std::string majestyId;
    std::string name;
    float majesty;         // 0.0 to 1.0
    float holiness;        // 0.0 to 1.0
    float grandeur;      // 0.0 to 1.0
    float dignity;       // 0.0 to 1.0
    bool isMajestic;
    int64_t createdAt;
    
    nlohmann::json ToJson() const;
    static MajestyHoly FromJson(const nlohmann::json& j);
};

struct PowerHoly {
    std::string powerId;
    std::string name;
    float power;           // 0.0 to 1.0
    float holiness;        // 0.0 to 1.0
    float strength;      // 0.0 to 1.0
    float might;         // 0.0 to 1.0
    int64_t createdAt;
    
    nlohmann::json ToJson() const;
    static PowerHoly FromJson(const nlohmann::json& j);
};

// Core engine class
class HolySovereigntyEngine {
public:
    // Initialization
    static void Init();
    static void Shutdown();
    static bool IsInitialized();
    
    // Holy Sovereignty Structure operations
    static std::string CreateHolySovereigntyStructure(const std::string& name);
    static bool DestroyHolySovereigntyStructure(const std::string& holyId);
    static std::shared_ptr<HolySovereigntyStructure> GetHolySovereigntyStructure(const std::string& holyId);
    static std::vector<HolySovereigntyStructure> GetAllHolySovereigntyStructures();
    static bool ElevateHoliness(const std::string& holyId, float amount);
    static bool ExpandSovereignty(const std::string& holyId, float amount);
    static bool BestowGlory(const std::string& holyId, float amount);
    static bool CrownMajesty(const std::string& holyId, float amount);
    static bool ChannelPower(const std::string& holyId, float amount);
    
    // Sovereignty Holy operations
    static std::string CreateSovereigntyHoly(const std::string& name);
    static bool DestroySovereigntyHoly(const std::string& sovereigntyId);
    static std::shared_ptr<SovereigntyHoly> GetSovereigntyHoly(const std::string& sovereigntyId);
    static std::vector<SovereigntyHoly> GetAllSovereigntyHolies();
    static bool AssertSupremacy(const std::string& sovereigntyId, float amount);
    static bool ExtendDominion(const std::string& sovereigntyId, float amount);
    static bool DeclareSupreme(const std::string& sovereigntyId);
    
    // Glory Holy operations
    static std::string CreateGloryHoly(const std::string& name);
    static bool DestroyGloryHoly(const std::string& gloryId);
    static std::shared_ptr<GloryHoly> GetGloryHoly(const std::string& gloryId);
    static std::vector<GloryHoly> GetAllGloryHolies();
    static bool RadiateBrilliance(const std::string& gloryId, float amount);
    static bool ManifestSplendor(const std::string& gloryId, float amount);
    
    // Majesty Holy operations
    static std::string CreateMajestyHoly(const std::string& name);
    static bool DestroyMajestyHoly(const std::string& majestyId);
    static std::shared_ptr<MajestyHoly> GetMajestyHoly(const std::string& majestyId);
    static std::vector<MajestyHoly> GetAllMajestyHolies();
    static bool ExaltGrandeur(const std::string& majestyId, float amount);
    static bool UpholdDignity(const std::string& majestyId, float amount);
    static bool DeclareMajestic(const std::string& majestyId);
    
    // Power Holy operations
    static std::string CreatePowerHoly(const std::string& name);
    static bool DestroyPowerHoly(const std::string& powerId);
    static std::shared_ptr<PowerHoly> GetPowerHoly(const std::string& powerId);
    static std::vector<PowerHoly> GetAllPowerHolies();
    static bool FortifyStrength(const std::string& powerId, float amount);
    static bool DemonstrateMight(const std::string& powerId, float amount);
    
    // Metrics and reporting
    static nlohmann::json GetHolySovereigntyMetrics();
    static nlohmann::json GenerateHolySovereigntyReport();
    
private:
    static bool s_initialized;
    static std::mutex s_holyMutex;
    static std::mutex s_sovereigntyMutex;
    static std::mutex s_gloryMutex;
    static std::mutex s_majestyMutex;
    static std::mutex s_powerMutex;
    
    static std::vector<std::shared_ptr<HolySovereigntyStructure>> s_holyStructures;
    static std::vector<std::shared_ptr<SovereigntyHoly>> s_sovereigntyHolies;
    static std::vector<std::shared_ptr<GloryHoly>> s_gloryHolies;
    static std::vector<std::shared_ptr<MajestyHoly>> s_majestyHolies;
    static std::vector<std::shared_ptr<PowerHoly>> s_powerHolies;
    
    static std::atomic<int64_t> s_holyCounter;
    static std::atomic<int64_t> s_sovereigntyCounter;
    static std::atomic<int64_t> s_gloryCounter;
    static std::atomic<int64_t> s_majestyCounter;
    static std::atomic<int64_t> s_powerCounter;
};

} // namespace HolySovereignty
