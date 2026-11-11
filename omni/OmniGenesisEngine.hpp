#pragma once

#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <atomic>
#include <nlohmann/json.hpp>

namespace OmniGenesis {

// Forward declarations
struct OmniGenesisStructure;
struct GenesisOmni;
struct CreationOmni;
struct OriginOmni;
struct SourceOmni;

// Core data structures
struct OmniGenesisStructure {
    std::string omniId;
    std::string name;
    float omniscience;     // 0.0 to 1.0
    float genesis;         // 0.0 to 1.0
    float creation;        // 0.0 to 1.0
    float origin;          // 0.0 to 1.0
    float source;          // 0.0 to 1.0
    int64_t createdAt;
    int64_t lastModified;
    bool isActive;
    
    nlohmann::json ToJson() const;
    static OmniGenesisStructure FromJson(const nlohmann::json& j);
};

struct GenesisOmni {
    std::string genesisId;
    std::string name;
    float genesis;         // 0.0 to 1.0
    float omniscience;     // 0.0 to 1.0
    float birth;       // 0.0 to 1.0
    float emergence;   // 0.0 to 1.0
    bool isBorn;
    int64_t createdAt;
    
    nlohmann::json ToJson() const;
    static GenesisOmni FromJson(const nlohmann::json& j);
};

struct CreationOmni {
    std::string creationId;
    std::string name;
    float creation;        // 0.0 to 1.0
    float omniscience;     // 0.0 to 1.0
    float manifestation; // 0.0 to 1.0
    float formation;       // 0.0 to 1.0
    int64_t createdAt;
    
    nlohmann::json ToJson() const;
    static CreationOmni FromJson(const nlohmann::json& j);
};

struct OriginOmni {
    std::string originId;
    std::string name;
    float origin;          // 0.0 to 1.0
    float omniscience;     // 0.0 to 1.0
    float beginning;   // 0.0 to 1.0
    float inception;   // 0.0 to 1.0
    bool isOriginated;
    int64_t createdAt;
    
    nlohmann::json ToJson() const;
    static OriginOmni FromJson(const nlohmann::json& j);
};

struct SourceOmni {
    std::string sourceId;
    std::string name;
    float source;          // 0.0 to 1.0
    float omniscience;     // 0.0 to 1.0
    float fountain;    // 0.0 to 1.0
    float wellspring;  // 0.0 to 1.0
    int64_t createdAt;
    
    nlohmann::json ToJson() const;
    static SourceOmni FromJson(const nlohmann::json& j);
};

// Core engine class
class OmniGenesisEngine {
public:
    // Initialization
    static void Init();
    static void Shutdown();
    static bool IsInitialized();
    
    // Omni Genesis Structure operations
    static std::string CreateOmniGenesisStructure(const std::string& name);
    static bool DestroyOmniGenesisStructure(const std::string& omniId);
    static std::shared_ptr<OmniGenesisStructure> GetOmniGenesisStructure(const std::string& omniId);
    static std::vector<OmniGenesisStructure> GetAllOmniGenesisStructures();
    static bool ExpandOmniscience(const std::string& omniId, float amount);
    static bool CatalyzeGenesis(const std::string& omniId, float amount);
    static bool ManifestCreation(const std::string& omniId, float amount);
    static bool EstablishOrigin(const std::string& omniId, float amount);
    static bool TapSource(const std::string& omniId, float amount);
    
    // Genesis Omni operations
    static std::string CreateGenesisOmni(const std::string& name);
    static bool DestroyGenesisOmni(const std::string& genesisId);
    static std::shared_ptr<GenesisOmni> GetGenesisOmni(const std::string& genesisId);
    static std::vector<GenesisOmni> GetAllGenesisOmnis();
    static bool NurtureBirth(const std::string& genesisId, float amount);
    static bool FosterEmergence(const std::string& genesisId, float amount);
    static bool DeclareBorn(const std::string& genesisId);
    
    // Creation Omni operations
    static std::string CreateCreationOmni(const std::string& name);
    static bool DestroyCreationOmni(const std::string& creationId);
    static std::shared_ptr<CreationOmni> GetCreationOmni(const std::string& creationId);
    static std::vector<CreationOmni> GetAllCreationOmnis();
    static bool EnableManifestation(const std::string& creationId, float amount);
    static bool GuideFormation(const std::string& creationId, float amount);
    
    // Origin Omni operations
    static std::string CreateOriginOmni(const std::string& name);
    static bool DestroyOriginOmni(const std::string& originId);
    static std::shared_ptr<OriginOmni> GetOriginOmni(const std::string& originId);
    static std::vector<OriginOmni> GetAllOriginOmnis();
    static bool MarkBeginning(const std::string& originId, float amount);
    static bool CommenceInception(const std::string& originId, float amount);
    static bool DeclareOriginated(const std::string& originId);
    
    // Source Omni operations
    static std::string CreateSourceOmni(const std::string& name);
    static bool DestroySourceOmni(const std::string& sourceId);
    static std::shared_ptr<SourceOmni> GetSourceOmni(const std::string& sourceId);
    static std::vector<SourceOmni> GetAllSourceOmnis();
    static bool ChannelFountain(const std::string& sourceId, float amount);
    static bool AccessWellspring(const std::string& sourceId, float amount);
    
    // Metrics and reporting
    static nlohmann::json GetOmniGenesisMetrics();
    static nlohmann::json GenerateOmniGenesisReport();
    
private:
    static bool s_initialized;
    static std::mutex s_omniMutex;
    static std::mutex s_genesisMutex;
    static std::mutex s_creationMutex;
    static std::mutex s_originMutex;
    static std::mutex s_sourceMutex;
    
    static std::vector<std::shared_ptr<OmniGenesisStructure>> s_omniStructures;
    static std::vector<std::shared_ptr<GenesisOmni>> s_genesisOmnis;
    static std::vector<std::shared_ptr<CreationOmni>> s_creationOmnis;
    static std::vector<std::shared_ptr<OriginOmni>> s_originOmnis;
    static std::vector<std::shared_ptr<SourceOmni>> s_sourceOmnis;
    
    static std::atomic<int64_t> s_omniCounter;
    static std::atomic<int64_t> s_genesisCounter;
    static std::atomic<int64_t> s_creationCounter;
    static std::atomic<int64_t> s_originCounter;
    static std::atomic<int64_t> s_sourceCounter;
};

} // namespace OmniGenesis
