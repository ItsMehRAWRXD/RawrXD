#pragma once

#include <cstring>
#include <vector>
#include <memory>
#include <mutex>
#include <atomic>
#include <nlohmann/json.hpp>

namespace SacredSovereignty {

// Forward declarations
struct SacredSovereigntyStructure;
struct SovereigntySacred;
struct AuthoritySacred;
struct DominionSacred;
struct SupremacySacred;

// Core data structures
struct SacredSovereigntyStructure {
    std::string sacredId;
    std::string name;
    float sacredness;      // 0.0 to 1.0
    float sovereignty;     // 0.0 to 1.0
    float authority;       // 0.0 to 1.0
    float dominion;        // 0.0 to 1.0
    float supremacy;       // 0.0 to 1.0
    int64_t createdAt;
    int64_t lastModified;
    bool isActive;
    
    nlohmann::json ToJson() const;
    static SacredSovereigntyStructure FromJson(const nlohmann::json& j);
};

struct SovereigntySacred {
    std::string sovereigntyId;
    std::string name;
    float sovereignty;     // 0.0 to 1.0
    float sacredness;      // 0.0 to 1.0
    float rule;          // 0.0 to 1.0
    float reign;         // 0.0 to 1.0
    bool isAbsolute;
    int64_t createdAt;
    
    nlohmann::json ToJson() const;
    static SovereigntySacred FromJson(const nlohmann::json& j);
};

struct AuthoritySacred {
    std::string authorityId;
    std::string name;
    float authority;       // 0.0 to 1.0
    float sacredness;      // 0.0 to 1.0
    float command;       // 0.0 to 1.0
    float control;       // 0.0 to 1.0
    int64_t createdAt;
    
    nlohmann::json ToJson() const;
    static AuthoritySacred FromJson(const nlohmann::json& j);
};

struct DominionSacred {
    std::string dominionId;
    std::string name;
    float dominion;        // 0.0 to 1.0
    float sacredness;      // 0.0 to 1.0
    float territory;     // 0.0 to 1.0
    float realm;         // 0.0 to 1.0
    bool isVast;
    int64_t createdAt;
    
    nlohmann::json ToJson() const;
    static DominionSacred FromJson(const nlohmann::json& j);
};

struct SupremacySacred {
    std::string supremacyId;
    std::string name;
    float supremacy;       // 0.0 to 1.0
    float sacredness;      // 0.0 to 1.0
    float dominance;     // 0.0 to 1.0
    float preeminence;   // 0.0 to 1.0
    int64_t createdAt;
    
    nlohmann::json ToJson() const;
    static SupremacySacred FromJson(const nlohmann::json& j);
};

// Core engine class
class SacredSovereigntyEngine {
public:
    // Initialization
    static void Init();
    static void Shutdown();
    static bool IsInitialized();
    
    // Sacred Sovereignty Structure operations
    static std::string CreateSacredSovereigntyStructure(const std::string& name);
    static bool DestroySacredSovereigntyStructure(const std::string& sacredId);
    static std::shared_ptr<SacredSovereigntyStructure> GetSacredSovereigntyStructure(const std::string& sacredId);
    static std::vector<SacredSovereigntyStructure> GetAllSacredSovereigntyStructures();
    static bool ElevateSacredness(const std::string& sacredId, float amount);
    static bool ExpandSovereignty(const std::string& sacredId, float amount);
    static bool AssertAuthority(const std::string& sacredId, float amount);
    static bool ExtendDominion(const std::string& sacredId, float amount);
    static bool AchieveSupremacy(const std::string& sacredId, float amount);
    
    // Sovereignty Sacred operations
    static std::string CreateSovereigntySacred(const std::string& name);
    static bool DestroySovereigntySacred(const std::string& sovereigntyId);
    static std::shared_ptr<SovereigntySacred> GetSovereigntySacred(const std::string& sovereigntyId);
    static std::vector<SovereigntySacred> GetAllSovereigntySacreds();
    static bool EstablishRule(const std::string& sovereigntyId, float amount);
    static bool ExtendReign(const std::string& sovereigntyId, float amount);
    static bool DeclareAbsolute(const std::string& sovereigntyId);
    
    // Authority Sacred operations
    static std::string CreateAuthoritySacred(const std::string& name);
    static bool DestroyAuthoritySacred(const std::string& authorityId);
    static std::shared_ptr<AuthoritySacred> GetAuthoritySacred(const std::string& authorityId);
    static std::vector<AuthoritySacred> GetAllAuthoritySacreds();
    static bool IssueCommand(const std::string& authorityId, float amount);
    static bool SeizeControl(const std::string& authorityId, float amount);
    
    // Dominion Sacred operations
    static std::string CreateDominionSacred(const std::string& name);
    static bool DestroyDominionSacred(const std::string& dominionId);
    static std::shared_ptr<DominionSacred> GetDominionSacred(const std::string& dominionId);
    static std::vector<DominionSacred> GetAllDominionSacreds();
    static bool ExpandTerritory(const std::string& dominionId, float amount);
    static bool ClaimRealm(const std::string& dominionId, float amount);
    static bool DeclareVast(const std::string& dominionId);
    
    // Supremacy Sacred operations
    static std::string CreateSupremacySacred(const std::string& name);
    static bool DestroySupremacySacred(const std::string& supremacyId);
    static std::shared_ptr<SupremacySacred> GetSupremacySacred(const std::string& supremacyId);
    static std::vector<SupremacySacred> GetAllSupremacySacreds();
    static bool AssertDominance(const std::string& supremacyId, float amount);
    static bool EstablishPreeminence(const std::string& supremacyId, float amount);
    
    // Metrics and reporting
    static nlohmann::json GetSacredSovereigntyMetrics();
    static nlohmann::json GenerateSacredSovereigntyReport();
    
private:
    static bool s_initialized;
    static std::mutex s_sacredMutex;
    static std::mutex s_sovereigntyMutex;
    static std::mutex s_authorityMutex;
    static std::mutex s_dominionMutex;
    static std::mutex s_supremacyMutex;
    
    static std::vector<std::shared_ptr<SacredSovereigntyStructure>> s_sacredStructures;
    static std::vector<std::shared_ptr<SovereigntySacred>> s_sovereigntySacreds;
    static std::vector<std::shared_ptr<AuthoritySacred>> s_authoritySacreds;
    static std::vector<std::shared_ptr<DominionSacred>> s_dominionSacreds;
    static std::vector<std::shared_ptr<SupremacySacred>> s_supremacySacreds;
    
    static std::atomic<int64_t> s_sacredCounter;
    static std::atomic<int64_t> s_sovereigntyCounter;
    static std::atomic<int64_t> s_authorityCounter;
    static std::atomic<int64_t> s_dominionCounter;
    static std::atomic<int64_t> s_supremacyCounter;
};

} // namespace SacredSovereignty
