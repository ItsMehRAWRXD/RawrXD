#pragma once

#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <atomic>
#include <nlohmann/json.hpp>

namespace Sacred {

struct SacredStructure {
    std::string sacredId;
    std::string name;
    float sacredness;
    float infinity;
    float divinity;
    float purity;
    float transcendence;
    bool isActive;
    int64_t createdAt;
    int64_t lastModified;
    std::map<std::string, std::string> attributes;
    std::vector<std::string> sacredEntities;
};

struct InfiniteSacred {
    std::string infiniteId;
    std::string name;
    float infinitude;
    float sacredness;
    float perpetuity;
    bool isInfinite;
    int64_t establishedAt;
    std::vector<std::string> infiniteAspects;
};

struct HolyInfinite {
    std::string holyId;
    std::string name;
    float holiness;
    float infinitude;
    float grace;
    float blessing;
    bool isManifest;
    int64_t manifestedAt;
    std::vector<std::string> holyManifestations;
};

struct BlessedInfinite {
    std::string blessedId;
    std::string name;
    float blessedness;
    float infinity;
    float favor;
    bool isBlessed;
    int64_t realizedAt;
    std::map<std::string, float> blessings;
};

struct SanctifiedInfinite {
    std::string sanctifiedId;
    std::string name;
    float sanctification;
    float infinity;
    float consecration;
    bool isSanctified;
    int64_t discoveredAt;
    std::vector<std::string> sanctifiedAspects;
};

class SacredInfinityEngine {
public:
    static void Init();
    static void Shutdown();
    static void OnTick();
    
    // Sacred Structure Management
    static std::string CreateSacredStructure(const std::string& name);
    static bool DestroySacredStructure(const std::string& sacredId);
    static SacredStructure* GetSacredStructure(const std::string& sacredId);
    static std::vector<SacredStructure> GetAllStructures();
    static void ExpandSacredness(const std::string& sacredId, float amount);
    static void DeepenInfinity(const std::string& sacredId, float amount);
    static void IncreaseDivinity(const std::string& sacredId, float amount);
    static void Purify(const std::string& sacredId, float amount);
    static void Transcend(const std::string& sacredId, float amount);
    
    // Infinite Sacred Management
    static std::string EstablishInfiniteSacred(const std::string& name);
    static bool DissolveInfiniteSacred(const std::string& infiniteId);
    static InfiniteSacred* GetInfiniteSacred(const std::string& infiniteId);
    static std::vector<InfiniteSacred> GetAllInfiniteSacreds();
    static void ExpandInfinitude(const std::string& infiniteId, float amount);
    static void IncreaseSacredness(const std::string& infiniteId, float amount);
    static void ExtendPerpetuity(const std::string& infiniteId, float amount);
    static void DeclareInfinite(const std::string& infiniteId);
    
    // Holy Infinite Management
    static std::string ManifestHolyInfinite(const std::string& name);
    static bool BanishHolyInfinite(const std::string& holyId);
    static HolyInfinite* GetHolyInfinite(const std::string& holyId);
    static std::vector<HolyInfinite> GetAllHolyInfinites();
    static void ElevateHoliness(const std::string& holyId, float amount);
    static void ExpandInfinitudeHoly(const std::string& holyId, float amount);
    static void BestowGrace(const std::string& holyId, float amount);
    static void GrantBlessing(const std::string& holyId, float amount);
    
    // Blessed Infinite Management
    static std::string RealizeBlessedInfinite(const std::string& name);
    static bool ReleaseBlessedInfinite(const std::string& blessedId);
    static BlessedInfinite* GetBlessedInfinite(const std::string& blessedId);
    static std::vector<BlessedInfinite> GetAllBlessedInfinites();
    static void AmplifyBlessedness(const std::string& blessedId, float amount);
    static void ExpandInfinity(const std::string& blessedId, float amount);
    static void IncreaseFavor(const std::string& blessedId, float amount);
    static void DeclareBlessed(const std::string& blessedId);
    
    // Sanctified Infinite Management
    static std::string DiscoverSanctifiedInfinite(const std::string& name);
    static bool ConcealSanctifiedInfinite(const std::string& sanctifiedId);
    static SanctifiedInfinite* GetSanctifiedInfinite(const std::string& sanctifiedId);
    static std::vector<SanctifiedInfinite> GetAllSanctifiedInfinites();
    static void IncreaseSanctification(const std::string& sanctifiedId, float amount);
    static void DeepenInfinity(const std::string& sanctifiedId, float amount);
    static void Consecrate(const std::string& sanctifiedId, float amount);
    
    // Metrics and Reporting
    static nlohmann::json GetSacredMetrics();
    static nlohmann::json GenerateSacredReport();
    static int64_t GetTickCount();
    
private:
    static std::atomic<bool> s_initialized;
    static std::atomic<int64_t> s_tickCount;
    static std::mutex s_structureMutex;
    static std::mutex s_infiniteMutex;
    static std::mutex s_holyMutex;
    static std::mutex s_blessedMutex;
    static std::mutex s_sanctifiedMutex;
    static std::map<std::string, SacredStructure> s_structures;
    static std::map<std::string, InfiniteSacred> s_infinites;
    static std::map<std::string, HolyInfinite> s_holies;
    static std::map<std::string, BlessedInfinite> s_blessed;
    static std::map<std::string, SanctifiedInfinite> s_sanctified;
    
    static std::string GenerateSacredId();
    static std::string GenerateInfiniteId();
    static std::string GenerateHolyId();
    static std::string GenerateBlessedId();
    static std::string GenerateSanctifiedId();
};

} // namespace Sacred
