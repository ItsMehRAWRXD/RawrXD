#pragma once

#include <cstring>
#include <vector>
#include <map>
#include <mutex>
#include <atomic>
#include <nlohmann/json.hpp>

namespace SacredDominion {

struct SacredStructure {
    std::string sacredId;
    std::string name;
    float sacredness;
    float dominion;
    float authority;
    float reverence;
    float sanctity;
    bool isActive;
    int64_t createdAt;
    int64_t lastModified;
    std::map<std::string, std::string> attributes;
    std::vector<std::string> sacredEntities;
};

struct DominionSacred {
    std::string dominionId;
    std::string name;
    float dominion;
    float sacredness;
    float sovereignty;
    bool isDominion;
    int64_t establishedAt;
    std::vector<std::string> dominionAspects;
};

struct HolySacred {
    std::string holyId;
    std::string name;
    float holiness;
    float sacredness;
    float grace;
    float blessing;
    bool isManifest;
    int64_t manifestedAt;
    std::vector<std::string> holyManifestations;
};

struct BlessedSacred {
    std::string blessedId;
    std::string name;
    float blessedness;
    float sacredness;
    float favor;
    bool isBlessed;
    int64_t realizedAt;
    std::map<std::string, float> blessings;
};

struct SanctifiedSacred {
    std::string sanctifiedId;
    std::string name;
    float sanctification;
    float sacredness;
    float consecration;
    bool isSanctified;
    int64_t discoveredAt;
    std::vector<std::string> sanctifiedAspects;
};

class SacredDominionEngine {
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
    static void ExtendDominion(const std::string& sacredId, float amount);
    static void IncreaseAuthority(const std::string& sacredId, float amount);
    static void DeepenReverence(const std::string& sacredId, float amount);
    static void ElevateSanctity(const std::string& sacredId, float amount);
    
    // Dominion Sacred Management
    static std::string EstablishDominionSacred(const std::string& name);
    static bool DissolveDominionSacred(const std::string& dominionId);
    static DominionSacred* GetDominionSacred(const std::string& dominionId);
    static std::vector<DominionSacred> GetAllDominionSacreds();
    static void ExpandDominion(const std::string& dominionId, float amount);
    static void IncreaseSacredness(const std::string& dominionId, float amount);
    static void AssertSovereignty(const std::string& dominionId, float amount);
    static void DeclareDominion(const std::string& dominionId);
    
    // Holy Sacred Management
    static std::string ManifestHolySacred(const std::string& name);
    static bool BanishHolySacred(const std::string& holyId);
    static HolySacred* GetHolySacred(const std::string& holyId);
    static std::vector<HolySacred> GetAllHolySacreds();
    static void ElevateHoliness(const std::string& holyId, float amount);
    static void ExpandSacrednessHoly(const std::string& holyId, float amount);
    static void BestowGrace(const std::string& holyId, float amount);
    static void GrantBlessing(const std::string& holyId, float amount);
    
    // Blessed Sacred Management
    static std::string RealizeBlessedSacred(const std::string& name);
    static bool ReleaseBlessedSacred(const std::string& blessedId);
    static BlessedSacred* GetBlessedSacred(const std::string& blessedId);
    static std::vector<BlessedSacred> GetAllBlessedSacreds();
    static void AmplifyBlessedness(const std::string& blessedId, float amount);
    static void ExpandSacrednessBlessed(const std::string& blessedId, float amount);
    static void IncreaseFavor(const std::string& blessedId, float amount);
    static void DeclareBlessed(const std::string& blessedId);
    
    // Sanctified Sacred Management
    static std::string DiscoverSanctifiedSacred(const std::string& name);
    static bool ConcealSanctifiedSacred(const std::string& sanctifiedId);
    static SanctifiedSacred* GetSanctifiedSacred(const std::string& sanctifiedId);
    static std::vector<SanctifiedSacred> GetAllSanctifiedSacreds();
    static void IncreaseSanctification(const std::string& sanctifiedId, float amount);
    static void ExpandSacrednessSanctified(const std::string& sanctifiedId, float amount);
    static void Consecrate(const std::string& sanctifiedId, float amount);
    
    // Metrics and Reporting
    static nlohmann::json GetSacredMetrics();
    static nlohmann::json GenerateSacredReport();
    static int64_t GetTickCount();
    
private:
    static std::atomic<bool> s_initialized;
    static std::atomic<int64_t> s_tickCount;
    static std::mutex s_structureMutex;
    static std::mutex s_dominionMutex;
    static std::mutex s_holyMutex;
    static std::mutex s_blessedMutex;
    static std::mutex s_sanctifiedMutex;
    static std::map<std::string, SacredStructure> s_structures;
    static std::map<std::string, DominionSacred> s_dominions;
    static std::map<std::string, HolySacred> s_holies;
    static std::map<std::string, BlessedSacred> s_blessed;
    static std::map<std::string, SanctifiedSacred> s_sanctified;
    
    static std::string GenerateSacredId();
    static std::string GenerateDominionId();
    static std::string GenerateHolyId();
    static std::string GenerateBlessedId();
    static std::string GenerateSanctifiedId();
};

} // namespace SacredDominion
