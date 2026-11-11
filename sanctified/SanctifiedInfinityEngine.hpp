#pragma once

#include <cstring>
#include <vector>
#include <map>
#include <mutex>
#include <atomic>
#include <nlohmann/json.hpp>

namespace Sanctified {

struct SanctifiedStructure {
    std::string sanctifiedId;
    std::string name;
    float sanctification;
    float infinity;
    float purity;
    float consecration;
    float devotion;
    bool isActive;
    int64_t createdAt;
    int64_t lastModified;
    std::map<std::string, std::string> attributes;
    std::vector<std::string> sanctifiedEntities;
};

struct InfiniteSanctified {
    std::string infiniteId;
    std::string name;
    float infinitude;
    float sanctification;
    float perpetuity;
    bool isInfinite;
    int64_t establishedAt;
    std::vector<std::string> infiniteAspects;
};

struct DivineSanctified {
    std::string divineId;
    std::string name;
    float divinity;
    float sanctification;
    float grace;
    float glory;
    bool isManifest;
    int64_t manifestedAt;
    std::vector<std::string> divineManifestations;
};

struct SacredSanctified {
    std::string sacredId;
    std::string name;
    float sacredness;
    float sanctification;
    float reverence;
    bool isSacred;
    int64_t realizedAt;
    std::map<std::string, float> blessings;
};

struct HolySanctified {
    std::string holyId;
    std::string name;
    float holiness;
    float sanctification;
    float consecration;
    bool isHoly;
    int64_t discoveredAt;
    std::vector<std::string> holyAspects;
};

class SanctifiedInfinityEngine {
public:
    static void Init();
    static void Shutdown();
    static void OnTick();
    
    // Sanctified Structure Management
    static std::string CreateSanctifiedStructure(const std::string& name);
    static bool DestroySanctifiedStructure(const std::string& sanctifiedId);
    static SanctifiedStructure* GetSanctifiedStructure(const std::string& sanctifiedId);
    static std::vector<SanctifiedStructure> GetAllStructures();
    static void ExpandSanctification(const std::string& sanctifiedId, float amount);
    static void DeepenInfinity(const std::string& sanctifiedId, float amount);
    static void Purify(const std::string& sanctifiedId, float amount);
    static void Consecrate(const std::string& sanctifiedId, float amount);
    static void IncreaseDevotion(const std::string& sanctifiedId, float amount);
    
    // Infinite Sanctified Management
    static std::string EstablishInfiniteSanctified(const std::string& name);
    static bool DissolveInfiniteSanctified(const std::string& infiniteId);
    static InfiniteSanctified* GetInfiniteSanctified(const std::string& infiniteId);
    static std::vector<InfiniteSanctified> GetAllInfiniteSanctifieds();
    static void ExpandInfinitude(const std::string& infiniteId, float amount);
    static void IncreaseSanctification(const std::string& infiniteId, float amount);
    static void ExtendPerpetuity(const std::string& infiniteId, float amount);
    static void DeclareInfinite(const std::string& infiniteId);
    
    // Divine Sanctified Management
    static std::string ManifestDivineSanctified(const std::string& name);
    static bool BanishDivineSanctified(const std::string& divineId);
    static DivineSanctified* GetDivineSanctified(const std::string& divineId);
    static std::vector<DivineSanctified> GetAllDivineSanctifieds();
    static void ElevateDivinity(const std::string& divineId, float amount);
    static void ExpandSanctificationDivine(const std::string& divineId, float amount);
    static void BestowGrace(const std::string& divineId, float amount);
    static void BestowGlory(const std::string& divineId, float amount);
    
    // Sacred Sanctified Management
    static std::string RealizeSacredSanctified(const std::string& name);
    static bool ReleaseSacredSanctified(const std::string& sacredId);
    static SacredSanctified* GetSacredSanctified(const std::string& sacredId);
    static std::vector<SacredSanctified> GetAllSacredSanctifieds();
    static void AmplifySacredness(const std::string& sacredId, float amount);
    static void ExpandSanctificationSacred(const std::string& sacredId, float amount);
    static void DeepenReverence(const std::string& sacredId, float amount);
    static void DeclareSacred(const std::string& sacredId);
    
    // Holy Sanctified Management
    static std::string DiscoverHolySanctified(const std::string& name);
    static bool ConcealHolySanctified(const std::string& holyId);
    static HolySanctified* GetHolySanctified(const std::string& holyId);
    static std::vector<HolySanctified> GetAllHolySanctifieds();
    static void IncreaseHoliness(const std::string& holyId, float amount);
    static void ExpandSanctificationHoly(const std::string& holyId, float amount);
    static void ConsecrateHoly(const std::string& holyId, float amount);
    
    // Metrics and Reporting
    static nlohmann::json GetSanctifiedMetrics();
    static nlohmann::json GenerateSanctifiedReport();
    static int64_t GetTickCount();
    
private:
    static std::atomic<bool> s_initialized;
    static std::atomic<int64_t> s_tickCount;
    static std::mutex s_structureMutex;
    static std::mutex s_infiniteMutex;
    static std::mutex s_divineMutex;
    static std::mutex s_sacredMutex;
    static std::mutex s_holyMutex;
    static std::map<std::string, SanctifiedStructure> s_structures;
    static std::map<std::string, InfiniteSanctified> s_infinites;
    static std::map<std::string, DivineSanctified> s_divines;
    static std::map<std::string, SacredSanctified> s_sacreds;
    static std::map<std::string, HolySanctified> s_holies;
    
    static std::string GenerateSanctifiedId();
    static std::string GenerateInfiniteId();
    static std::string GenerateDivineId();
    static std::string GenerateSacredId();
    static std::string GenerateHolyId();
};

} // namespace Sanctified
