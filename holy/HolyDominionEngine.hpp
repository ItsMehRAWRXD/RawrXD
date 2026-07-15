#pragma once

#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <atomic>
#include <nlohmann/json.hpp>

namespace Holy {

struct HolyStructure {
    std::string holyId;
    std::string name;
    float holiness;
    float dominion;
    float authority;
    float grace;
    float blessing;
    bool isActive;
    int64_t createdAt;
    int64_t lastModified;
    std::map<std::string, std::string> attributes;
    std::vector<std::string> holyEntities;
};

struct DominionHoly {
    std::string dominionId;
    std::string name;
    float dominion;
    float holiness;
    float sovereignty;
    bool isDominion;
    int64_t establishedAt;
    std::vector<std::string> dominionAspects;
};

struct SacredDominion {
    std::string sacredId;
    std::string name;
    float sacredness;
    float dominion;
    float reverence;
    float sanctity;
    bool isManifest;
    int64_t manifestedAt;
    std::vector<std::string> sacredManifestations;
};

struct BlessedDominion {
    std::string blessedId;
    std::string name;
    float blessedness;
    float dominion;
    float favor;
    bool isBlessed;
    int64_t realizedAt;
    std::map<std::string, float> blessings;
};

struct SanctifiedDominion {
    std::string sanctifiedId;
    std::string name;
    float sanctification;
    float dominion;
    float consecration;
    bool isSanctified;
    int64_t discoveredAt;
    std::vector<std::string> sanctifiedAspects;
};

class HolyDominionEngine {
public:
    static void Init();
    static void Shutdown();
    static void OnTick();
    
    // Holy Structure Management
    static std::string CreateHolyStructure(const std::string& name);
    static bool DestroyHolyStructure(const std::string& holyId);
    static HolyStructure* GetHolyStructure(const std::string& holyId);
    static std::vector<HolyStructure> GetAllStructures();
    static void ExpandHoliness(const std::string& holyId, float amount);
    static void ExtendDominion(const std::string& holyId, float amount);
    static void IncreaseAuthority(const std::string& holyId, float amount);
    static void BestowGrace(const std::string& holyId, float amount);
    static void GrantBlessing(const std::string& holyId, float amount);
    
    // Dominion Holy Management
    static std::string EstablishDominionHoly(const std::string& name);
    static bool DissolveDominionHoly(const std::string& dominionId);
    static DominionHoly* GetDominionHoly(const std::string& dominionId);
    static std::vector<DominionHoly> GetAllDominionHolies();
    static void ExpandDominion(const std::string& dominionId, float amount);
    static void IncreaseHoliness(const std::string& dominionId, float amount);
    static void AssertSovereignty(const std::string& dominionId, float amount);
    static void DeclareDominion(const std::string& dominionId);
    
    // Sacred Dominion Management
    static std::string ManifestSacredDominion(const std::string& name);
    static bool BanishSacredDominion(const std::string& sacredId);
    static SacredDominion* GetSacredDominion(const std::string& sacredId);
    static std::vector<SacredDominion> GetAllSacredDominions();
    static void ElevateSacredness(const std::string& sacredId, float amount);
    static void ExpandDominionSacred(const std::string& sacredId, float amount);
    static void DeepenReverence(const std::string& sacredId, float amount);
    static void IncreaseSanctity(const std::string& sacredId, float amount);
    
    // Blessed Dominion Management
    static std::string RealizeBlessedDominion(const std::string& name);
    static bool ReleaseBlessedDominion(const std::string& blessedId);
    static BlessedDominion* GetBlessedDominion(const std::string& blessedId);
    static std::vector<BlessedDominion> GetAllBlessedDominions();
    static void AmplifyBlessedness(const std::string& blessedId, float amount);
    static void ExtendDominion(const std::string& blessedId, float amount);
    static void IncreaseFavor(const std::string& blessedId, float amount);
    static void DeclareBlessed(const std::string& blessedId);
    
    // Sanctified Dominion Management
    static std::string DiscoverSanctifiedDominion(const std::string& name);
    static bool ConcealSanctifiedDominion(const std::string& sanctifiedId);
    static SanctifiedDominion* GetSanctifiedDominion(const std::string& sanctifiedId);
    static std::vector<SanctifiedDominion> GetAllSanctifiedDominions();
    static void IncreaseSanctification(const std::string& sanctifiedId, float amount);
    static void DeepenDominion(const std::string& sanctifiedId, float amount);
    static void Consecrate(const std::string& sanctifiedId, float amount);
    
    // Metrics and Reporting
    static nlohmann::json GetHolyMetrics();
    static nlohmann::json GenerateHolyReport();
    static int64_t GetTickCount();
    
private:
    static std::atomic<bool> s_initialized;
    static std::atomic<int64_t> s_tickCount;
    static std::mutex s_structureMutex;
    static std::mutex s_dominionMutex;
    static std::mutex s_sacredMutex;
    static std::mutex s_blessedMutex;
    static std::mutex s_sanctifiedMutex;
    static std::map<std::string, HolyStructure> s_structures;
    static std::map<std::string, DominionHoly> s_dominions;
    static std::map<std::string, SacredDominion> s_sacreds;
    static std::map<std::string, BlessedDominion> s_blessed;
    static std::map<std::string, SanctifiedDominion> s_sanctified;
    
    static std::string GenerateHolyId();
    static std::string GenerateDominionId();
    static std::string GenerateSacredId();
    static std::string GenerateBlessedId();
    static std::string GenerateSanctifiedId();
};

} // namespace Holy
