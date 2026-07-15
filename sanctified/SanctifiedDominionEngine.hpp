#pragma once

#include <cstring>
#include <vector>
#include <memory>
#include <mutex>
#include <atomic>
#include <nlohmann/json.hpp>

namespace SanctifiedDominion {

// Forward declarations
struct SanctifiedDominionStructure;
struct DominionSanctified;
struct PuritySanctified;
struct DevotionSanctified;
struct ConsecrationSanctified;

// Core data structures
struct SanctifiedDominionStructure {
    std::string sanctifiedId;
    std::string name;
    float sanctifiedness;  // 0.0 to 1.0
    float dominion;        // 0.0 to 1.0
    float purity;          // 0.0 to 1.0
    float devotion;        // 0.0 to 1.0
    float consecration;    // 0.0 to 1.0
    int64_t createdAt;
    int64_t lastModified;
    bool isActive;
    
    nlohmann::json ToJson() const;
    static SanctifiedDominionStructure FromJson(const nlohmann::json& j);
};

struct DominionSanctified {
    std::string dominionId;
    std::string name;
    float dominion;        // 0.0 to 1.0
    float sanctifiedness;  // 0.0 to 1.0
    float authority;       // 0.0 to 1.0
    float rule;          // 0.0 to 1.0
    bool isSupreme;
    int64_t createdAt;
    
    nlohmann::json ToJson() const;
    static DominionSanctified FromJson(const nlohmann::json& j);
};

struct PuritySanctified {
    std::string purityId;
    std::string name;
    float purity;          // 0.0 to 1.0
    float sanctifiedness;  // 0.0 to 1.0
    float cleanliness;     // 0.0 to 1.0
    float innocence;       // 0.0 to 1.0
    int64_t createdAt;
    
    nlohmann::json ToJson() const;
    static PuritySanctified FromJson(const nlohmann::json& j);
};

struct DevotionSanctified {
    std::string devotionId;
    std::string name;
    float devotion;        // 0.0 to 1.0
    float sanctifiedness;  // 0.0 to 1.0
    float dedication;    // 0.0 to 1.0
    float commitment;    // 0.0 to 1.0
    bool isDevoted;
    int64_t createdAt;
    
    nlohmann::json ToJson() const;
    static DevotionSanctified FromJson(const nlohmann::json& j);
};

struct ConsecrationSanctified {
    std::string consecrationId;
    std::string name;
    float consecration;    // 0.0 to 1.0
    float sanctifiedness;  // 0.0 to 1.0
    float dedication;    // 0.0 to 1.0
    float sanctity;      // 0.0 to 1.0
    int64_t createdAt;
    
    nlohmann::json ToJson() const;
    static ConsecrationSanctified FromJson(const nlohmann::json& j);
};

// Core engine class
class SanctifiedDominionEngine {
public:
    // Initialization
    static void Init();
    static void Shutdown();
    static bool IsInitialized();
    
    // Sanctified Dominion Structure operations
    static std::string CreateSanctifiedDominionStructure(const std::string& name);
    static bool DestroySanctifiedDominionStructure(const std::string& sanctifiedId);
    static std::shared_ptr<SanctifiedDominionStructure> GetSanctifiedDominionStructure(const std::string& sanctifiedId);
    static std::vector<SanctifiedDominionStructure> GetAllSanctifiedDominionStructures();
    static bool ElevateSanctifiedness(const std::string& sanctifiedId, float amount);
    static bool ExpandDominion(const std::string& sanctifiedId, float amount);
    static bool BestowPurity(const std::string& sanctifiedId, float amount);
    static bool InspireDevotion(const std::string& sanctifiedId, float amount);
    static bool PerformConsecration(const std::string& sanctifiedId, float amount);
    
    // Dominion Sanctified operations
    static std::string CreateDominionSanctified(const std::string& name);
    static bool DestroyDominionSanctified(const std::string& dominionId);
    static std::shared_ptr<DominionSanctified> GetDominionSanctified(const std::string& dominionId);
    static std::vector<DominionSanctified> GetAllDominionSanctifieds();
    static bool AssertAuthority(const std::string& dominionId, float amount);
    static bool EstablishRule(const std::string& dominionId, float amount);
    static bool DeclareSupreme(const std::string& dominionId);
    
    // Purity Sanctified operations
    static std::string CreatePuritySanctified(const std::string& name);
    static bool DestroyPuritySanctified(const std::string& purityId);
    static std::shared_ptr<PuritySanctified> GetPuritySanctified(const std::string& purityId);
    static std::vector<PuritySanctified> GetAllPuritySanctifieds();
    static bool Purify(const std::string& purityId, float amount);
    static bool RestoreInnocence(const std::string& purityId, float amount);
    
    // Devotion Sanctified operations
    static std::string CreateDevotionSanctified(const std::string& name);
    static bool DestroyDevotionSanctified(const std::string& devotionId);
    static std::shared_ptr<DevotionSanctified> GetDevotionSanctified(const std::string& devotionId);
    static std::vector<DevotionSanctified> GetAllDevotionSanctifieds();
    static bool DeepenDedication(const std::string& devotionId, float amount);
    static bool StrengthenCommitment(const std::string& devotionId, float amount);
    static bool DeclareDevoted(const std::string& devotionId);
    
    // Consecration Sanctified operations
    static std::string CreateConsecrationSanctified(const std::string& name);
    static bool DestroyConsecrationSanctified(const std::string& consecrationId);
    static std::shared_ptr<ConsecrationSanctified> GetConsecrationSanctified(const std::string& consecrationId);
    static std::vector<ConsecrationSanctified> GetAllConsecrationSanctifieds();
    static bool IntensifyDedication(const std::string& consecrationId, float amount);
    static bool ElevateSanctity(const std::string& consecrationId, float amount);
    
    // Metrics and reporting
    static nlohmann::json GetSanctifiedDominionMetrics();
    static nlohmann::json GenerateSanctifiedDominionReport();
    
private:
    static bool s_initialized;
    static std::mutex s_sanctifiedMutex;
    static std::mutex s_dominionMutex;
    static std::mutex s_purityMutex;
    static std::mutex s_devotionMutex;
    static std::mutex s_consecrationMutex;
    
    static std::vector<std::shared_ptr<SanctifiedDominionStructure>> s_sanctifiedStructures;
    static std::vector<std::shared_ptr<DominionSanctified>> s_dominionSanctifieds;
    static std::vector<std::shared_ptr<PuritySanctified>> s_puritySanctifieds;
    static std::vector<std::shared_ptr<DevotionSanctified>> s_devotionSanctifieds;
    static std::vector<std::shared_ptr<ConsecrationSanctified>> s_consecrationSanctifieds;
    
    static std::atomic<int64_t> s_sanctifiedCounter;
    static std::atomic<int64_t> s_dominionCounter;
    static std::atomic<int64_t> s_purityCounter;
    static std::atomic<int64_t> s_devotionCounter;
    static std::atomic<int64_t> s_consecrationCounter;
};

} // namespace SanctifiedDominion
