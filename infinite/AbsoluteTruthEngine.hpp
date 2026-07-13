#pragma once

#include <cstring>
#include <vector>
#include <memory>
#include <mutex>
#include <atomic>
#include <map>
#include <nlohmann/json.hpp>

namespace AbsoluteTruth {

// Forward declarations
struct AbsoluteTruthStructure;
struct VerityAbsolute;
struct FactAbsolute;
struct RealityAbsolute;
struct ActualityAbsolute;
struct CertaintyAbsolute;
struct ValidityAbsolute;

using json = nlohmann::json;

// Core data structures

struct AbsoluteTruthStructure {
    std::string id;
    std::string name;
    std::string description;
    
    // Absolute truth properties
    float verity;
    float factuality;
    float reality;
    float actuality;
    float certainty;
    float validity;
    
    // Metadata
    std::string createdAt;
    std::string modifiedAt;
    bool isActive;
    
    AbsoluteTruthStructure() : verity(0.0f), factuality(0.0f), reality(0.0f), 
                               actuality(0.0f), certainty(0.0f), validity(0.0f), 
                               isActive(true) {}
    
    json ToJson() const;
    static AbsoluteTruthStructure FromJson(const json& j);
};

struct VerityAbsolute {
    std::string id;
    std::string name;
    std::string parentId;
    
    float verity;
    float factuality;
    float reality;
    float actuality;
    float certainty;
    float validity;
    
    bool isAbsolute;
    std::string absolutizedAt;
    
    VerityAbsolute() : verity(0.0f), factuality(0.0f), reality(0.0f), 
                       actuality(0.0f), certainty(0.0f), validity(0.0f), 
                       isAbsolute(false) {}
    
    json ToJson() const;
    static VerityAbsolute FromJson(const json& j);
};

struct FactAbsolute {
    std::string id;
    std::string name;
    std::string parentId;
    
    float verity;
    float factuality;
    float reality;
    float actuality;
    float certainty;
    float validity;
    
    bool isAbsolute;
    std::string absolutizedAt;
    
    FactAbsolute() : verity(0.0f), factuality(0.0f), reality(0.0f), 
                     actuality(0.0f), certainty(0.0f), validity(0.0f), 
                     isAbsolute(false) {}
    
    json ToJson() const;
    static FactAbsolute FromJson(const json& j);
};

struct RealityAbsolute {
    std::string id;
    std::string name;
    std::string parentId;
    
    float verity;
    float factuality;
    float reality;
    float actuality;
    float certainty;
    float validity;
    
    bool isAbsolute;
    std::string absolutizedAt;
    
    RealityAbsolute() : verity(0.0f), factuality(0.0f), reality(0.0f), 
                      actuality(0.0f), certainty(0.0f), validity(0.0f), 
                      isAbsolute(false) {}
    
    json ToJson() const;
    static RealityAbsolute FromJson(const json& j);
};

struct ActualityAbsolute {
    std::string id;
    std::string name;
    std::string parentId;
    
    float verity;
    float factuality;
    float reality;
    float actuality;
    float certainty;
    float validity;
    
    bool isAbsolute;
    std::string absolutizedAt;
    
    ActualityAbsolute() : verity(0.0f), factuality(0.0f), reality(0.0f), 
                          actuality(0.0f), certainty(0.0f), validity(0.0f), 
                          isAbsolute(false) {}
    
    json ToJson() const;
    static ActualityAbsolute FromJson(const json& j);
};

struct CertaintyAbsolute {
    std::string id;
    std::string name;
    std::string parentId;
    
    float verity;
    float factuality;
    float reality;
    float actuality;
    float certainty;
    float validity;
    
    bool isAbsolute;
    std::string absolutizedAt;
    
    CertaintyAbsolute() : verity(0.0f), factuality(0.0f), reality(0.0f), 
                          actuality(0.0f), certainty(0.0f), validity(0.0f), 
                          isAbsolute(false) {}
    
    json ToJson() const;
    static CertaintyAbsolute FromJson(const json& j);
};

struct ValidityAbsolute {
    std::string id;
    std::string name;
    std::string parentId;
    
    float verity;
    float factuality;
    float reality;
    float actuality;
    float certainty;
    float validity;
    
    bool isAbsolute;
    std::string absolutizedAt;
    
    ValidityAbsolute() : verity(0.0f), factuality(0.0f), reality(0.0f), 
                         actuality(0.0f), certainty(0.0f), validity(0.0f), 
                         isAbsolute(false) {}
    
    json ToJson() const;
    static ValidityAbsolute FromJson(const json& j);
};

// Main engine class
class AbsoluteTruthEngine {
public:
    // Initialization
    static bool Initialize();
    static void Shutdown();
    static bool IsInitialized();
    
    // Absolute truth structure operations
    static std::string CreateAbsoluteTruthStructure(const std::string& name);
    static std::shared_ptr<AbsoluteTruthStructure> GetAbsoluteTruthStructure(const std::string& id);
    static bool UpdateAbsoluteTruthStructure(const std::string& id, const AbsoluteTruthStructure& structure);
    static bool DeleteAbsoluteTruthStructure(const std::string& id);
    static std::vector<std::string> GetAllAbsoluteTruthStructureIds();
    static std::vector<std::shared_ptr<AbsoluteTruthStructure>> GetAllAbsoluteTruthStructures();
    
    // Verity absolute operations
    static std::string CreateVerityAbsolute(const std::string& name, const std::string& parentId = "");
    static std::shared_ptr<VerityAbsolute> GetVerityAbsolute(const std::string& id);
    static bool UpdateVerityAbsolute(const std::string& id, const VerityAbsolute& verity);
    static bool DeleteVerityAbsolute(const std::string& id);
    static std::vector<std::string> GetAllVerityAbsoluteIds();
    static std::vector<std::shared_ptr<VerityAbsolute>> GetAllVerityAbsolutes();
    
    // Fact absolute operations
    static std::string CreateFactAbsolute(const std::string& name, const std::string& parentId = "");
    static std::shared_ptr<FactAbsolute> GetFactAbsolute(const std::string& id);
    static bool UpdateFactAbsolute(const std::string& id, const FactAbsolute& fact);
    static bool DeleteFactAbsolute(const std::string& id);
    static std::vector<std::string> GetAllFactAbsoluteIds();
    static std::vector<std::shared_ptr<FactAbsolute>> GetAllFactAbsolutes();
    
    // Reality absolute operations
    static std::string CreateRealityAbsolute(const std::string& name, const std::string& parentId = "");
    static std::shared_ptr<RealityAbsolute> GetRealityAbsolute(const std::string& id);
    static bool UpdateRealityAbsolute(const std::string& id, const RealityAbsolute& reality);
    static bool DeleteRealityAbsolute(const std::string& id);
    static std::vector<std::string> GetAllRealityAbsoluteIds();
    static std::vector<std::shared_ptr<RealityAbsolute>> GetAllRealityAbsolutes();
    
    // Actuality absolute operations
    static std::string CreateActualityAbsolute(const std::string& name, const std::string& parentId = "");
    static std::shared_ptr<ActualityAbsolute> GetActualityAbsolute(const std::string& id);
    static bool UpdateActualityAbsolute(const std::string& id, const ActualityAbsolute& actuality);
    static bool DeleteActualityAbsolute(const std::string& id);
    static std::vector<std::string> GetAllActualityAbsoluteIds();
    static std::vector<std::shared_ptr<ActualityAbsolute>> GetAllActualityAbsolutes();
    
    // Certainty absolute operations
    static std::string CreateCertaintyAbsolute(const std::string& name, const std::string& parentId = "");
    static std::shared_ptr<CertaintyAbsolute> GetCertaintyAbsolute(const std::string& id);
    static bool UpdateCertaintyAbsolute(const std::string& id, const CertaintyAbsolute& certainty);
    static bool DeleteCertaintyAbsolute(const std::string& id);
    static std::vector<std::string> GetAllCertaintyAbsoluteIds();
    static std::vector<std::shared_ptr<CertaintyAbsolute>> GetAllCertaintyAbsolutes();
    
    // Validity absolute operations
    static std::string CreateValidityAbsolute(const std::string& name, const std::string& parentId = "");
    static std::shared_ptr<ValidityAbsolute> GetValidityAbsolute(const std::string& id);
    static bool UpdateValidityAbsolute(const std::string& id, const ValidityAbsolute& validity);
    static bool DeleteValidityAbsolute(const std::string& id);
    static std::vector<std::string> GetAllValidityAbsoluteIds();
    static std::vector<std::shared_ptr<ValidityAbsolute>> GetAllValidityAbsolutes();
    
    // Action operations
    static bool ExpandAbsoluteTruth(const std::string& id);
    static bool AmplifyVerity(const std::string& id);
    static bool IncreaseFactuality(const std::string& id);
    static bool EnhanceReality(const std::string& id);
    static bool SolidifyActuality(const std::string& id);
    static bool StrengthenCertainty(const std::string& id);
    static bool ValidateAbsolute(const std::string& id);
    
    // Verity absolute actions
    static bool IntensifyVerityAbsolute(const std::string& id);
    static bool AffirmVerityAbsolute(const std::string& id);
    static bool DeclareVerityAbsolute(const std::string& id);
    
    // Fact absolute actions
    static bool VerifyFactAbsolute(const std::string& id);
    static bool EstablishFactAbsolute(const std::string& id);
    static bool DeclareFactAbsolute(const std::string& id);
    
    // Reality absolute actions
    static bool ManifestRealityAbsolute(const std::string& id);
    static bool GroundRealityAbsolute(const std::string& id);
    static bool DeclareRealityAbsolute(const std::string& id);
    
    // Actuality absolute actions
    static bool RealizeActualityAbsolute(const std::string& id);
    static bool EmbodyActualityAbsolute(const std::string& id);
    static bool DeclareActualityAbsolute(const std::string& id);
    
    // Certainty absolute actions
    static bool GuaranteeCertaintyAbsolute(const std::string& id);
    static bool SecureCertaintyAbsolute(const std::string& id);
    static bool DeclareCertaintyAbsolute(const std::string& id);
    
    // Validity absolute actions
    static bool ConfirmValidityAbsolute(const std::string& id);
    static bool AuthenticateValidityAbsolute(const std::string& id);
    static bool DeclareValidityAbsolute(const std::string& id);
    
    // Utility
    static void ClearAll();
    static size_t GetTotalStructureCount();
    
private:
    static std::atomic<bool> s_initialized;
    
    static std::mutex s_structureMutex;
    static std::mutex s_verityMutex;
    static std::mutex s_factMutex;
    static std::mutex s_realityMutex;
    static std::mutex s_actualityMutex;
    static std::mutex s_certaintyMutex;
    static std::mutex s_validityMutex;
    
    static std::map<std::string, std::shared_ptr<AbsoluteTruthStructure>> s_structures;
    static std::map<std::string, std::shared_ptr<VerityAbsolute>> s_verityAbsolutes;
    static std::map<std::string, std::shared_ptr<FactAbsolute>> s_factAbsolutes;
    static std::map<std::string, std::shared_ptr<RealityAbsolute>> s_realityAbsolutes;
    static std::map<std::string, std::shared_ptr<ActualityAbsolute>> s_actualityAbsolutes;
    static std::map<std::string, std::shared_ptr<CertaintyAbsolute>> s_certaintyAbsolutes;
    static std::map<std::string, std::shared_ptr<ValidityAbsolute>> s_validityAbsolutes;
    
    static std::string GenerateId();
    static std::string GetCurrentTimestamp();
};

} // namespace AbsoluteTruth
