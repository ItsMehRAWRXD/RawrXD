#pragma once

#include <cstring>
#include <vector>
#include <memory>
#include <mutex>
#include <atomic>
#include <nlohmann/json.hpp>

namespace BlessedDominion {

// Forward declarations
struct BlessedDominionStructure;
struct DominionBlessed;
struct GraceBlessed;
struct FavorBlessed;
struct ProvidenceBlessed;

// Core data structures
struct BlessedDominionStructure {
    std::string blessedId;
    std::string name;
    float blessedness;     // 0.0 to 1.0
    float dominion;        // 0.0 to 1.0
    float grace;         // 0.0 to 1.0
    float favor;         // 0.0 to 1.0
    float providence;    // 0.0 to 1.0
    int64_t createdAt;
    int64_t lastModified;
    bool isActive;
    
    nlohmann::json ToJson() const;
    static BlessedDominionStructure FromJson(const nlohmann::json& j);
};

struct DominionBlessed {
    std::string dominionId;
    std::string name;
    float dominion;        // 0.0 to 1.0
    float blessedness;     // 0.0 to 1.0
    float authority;       // 0.0 to 1.0
    float sovereignty;     // 0.0 to 1.0
    bool isSovereign;
    int64_t createdAt;
    
    nlohmann::json ToJson() const;
    static DominionBlessed FromJson(const nlohmann::json& j);
};

struct GraceBlessed {
    std::string graceId;
    std::string name;
    float grace;           // 0.0 to 1.0
    float blessedness;     // 0.0 to 1.0
    float mercy;         // 0.0 to 1.0
    float kindness;      // 0.0 to 1.0
    int64_t createdAt;
    
    nlohmann::json ToJson() const;
    static GraceBlessed FromJson(const nlohmann::json& j);
};

struct FavorBlessed {
    std::string favorId;
    std::string name;
    float favor;           // 0.0 to 1.0
    float blessedness;     // 0.0 to 1.0
    float preference;    // 0.0 to 1.0
    float approval;      // 0.0 to 1.0
    bool isPreferred;
    int64_t createdAt;
    
    nlohmann::json ToJson() const;
    static FavorBlessed FromJson(const nlohmann::json& j);
};

struct ProvidenceBlessed {
    std::string providenceId;
    std::string name;
    float providence;      // 0.0 to 1.0
    float blessedness;     // 0.0 to 1.0
    float guidance;      // 0.0 to 1.0
    float protection;    // 0.0 to 1.0
    int64_t createdAt;
    
    nlohmann::json ToJson() const;
    static ProvidenceBlessed FromJson(const nlohmann::json& j);
};

// Core engine class
class BlessedDominionEngine {
public:
    // Initialization
    static void Init();
    static void Shutdown();
    static bool IsInitialized();
    
    // Blessed Dominion Structure operations
    static std::string CreateBlessedDominionStructure(const std::string& name);
    static bool DestroyBlessedDominionStructure(const std::string& blessedId);
    static std::shared_ptr<BlessedDominionStructure> GetBlessedDominionStructure(const std::string& blessedId);
    static std::vector<BlessedDominionStructure> GetAllBlessedDominionStructures();
    static bool ElevateBlessedness(const std::string& blessedId, float amount);
    static bool ExpandDominion(const std::string& blessedId, float amount);
    static bool BestowGrace(const std::string& blessedId, float amount);
    static bool GrantFavor(const std::string& blessedId, float amount);
    static bool ProvideProvidence(const std::string& blessedId, float amount);
    
    // Dominion Blessed operations
    static std::string CreateDominionBlessed(const std::string& name);
    static bool DestroyDominionBlessed(const std::string& dominionId);
    static std::shared_ptr<DominionBlessed> GetDominionBlessed(const std::string& dominionId);
    static std::vector<DominionBlessed> GetAllDominionBlesseds();
    static bool AssertAuthority(const std::string& dominionId, float amount);
    static bool ClaimSovereignty(const std::string& dominionId, float amount);
    static bool DeclareSovereign(const std::string& dominionId);
    
    // Grace Blessed operations
    static std::string CreateGraceBlessed(const std::string& name);
    static bool DestroyGraceBlessed(const std::string& graceId);
    static std::shared_ptr<GraceBlessed> GetGraceBlessed(const std::string& graceId);
    static std::vector<GraceBlessed> GetAllGraceBlesseds();
    static bool ExtendMercy(const std::string& graceId, float amount);
    static bool ShowKindness(const std::string& graceId, float amount);
    
    // Favor Blessed operations
    static std::string CreateFavorBlessed(const std::string& name);
    static bool DestroyFavorBlessed(const std::string& favorId);
    static std::shared_ptr<FavorBlessed> GetFavorBlessed(const std::string& favorId);
    static std::vector<FavorBlessed> GetAllFavorBlesseds();
    static bool ExpressPreference(const std::string& favorId, float amount);
    static bool GrantApproval(const std::string& favorId, float amount);
    static bool DeclarePreferred(const std::string& favorId);
    
    // Providence Blessed operations
    static std::string CreateProvidenceBlessed(const std::string& name);
    static bool DestroyProvidenceBlessed(const std::string& providenceId);
    static std::shared_ptr<ProvidenceBlessed> GetProvidenceBlessed(const std::string& providenceId);
    static std::vector<ProvidenceBlessed> GetAllProvidenceBlesseds();
    static bool OfferGuidance(const std::string& providenceId, float amount);
    static bool ExtendProtection(const std::string& providenceId, float amount);
    
    // Metrics and reporting
    static nlohmann::json GetBlessedDominionMetrics();
    static nlohmann::json GenerateBlessedDominionReport();
    
private:
    static bool s_initialized;
    static std::mutex s_blessedMutex;
    static std::mutex s_dominionMutex;
    static std::mutex s_graceMutex;
    static std::mutex s_favorMutex;
    static std::mutex s_providenceMutex;
    
    static std::vector<std::shared_ptr<BlessedDominionStructure>> s_blessedStructures;
    static std::vector<std::shared_ptr<DominionBlessed>> s_dominionBlesseds;
    static std::vector<std::shared_ptr<GraceBlessed>> s_graceBlesseds;
    static std::vector<std::shared_ptr<FavorBlessed>> s_favorBlesseds;
    static std::vector<std::shared_ptr<ProvidenceBlessed>> s_providenceBlesseds;
    
    static std::atomic<int64_t> s_blessedCounter;
    static std::atomic<int64_t> s_dominionCounter;
    static std::atomic<int64_t> s_graceCounter;
    static std::atomic<int64_t> s_favorCounter;
    static std::atomic<int64_t> s_providenceCounter;
};

} // namespace BlessedDominion
