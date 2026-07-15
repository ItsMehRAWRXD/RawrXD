#pragma once

#include <cstring>
#include <vector>
#include <memory>
#include <mutex>
#include <atomic>
#include <nlohmann/json.hpp>

namespace CelestialEternity {

// Forward declarations
struct CelestialEternityStructure;
struct EternityCelestial;
struct CosmosCelestial;
struct FirmamentCelestial;
struct AetherCelestial;

// Core data structures
struct CelestialEternityStructure {
    std::string celestialId;
    std::string name;
    float celestialness;   // 0.0 to 1.0
    float eternity;        // 0.0 to 1.0
    float cosmos;          // 0.0 to 1.0
    float firmament;       // 0.0 to 1.0
    float aether;          // 0.0 to 1.0
    int64_t createdAt;
    int64_t lastModified;
    bool isActive;
    
    nlohmann::json ToJson() const;
    static CelestialEternityStructure FromJson(const nlohmann::json& j);
};

struct EternityCelestial {
    std::string eternityId;
    std::string name;
    float eternity;        // 0.0 to 1.0
    float celestialness;   // 0.0 to 1.0
    float infinity;    // 0.0 to 1.0
    float perpetuity;  // 0.0 to 1.0
    bool isEternal;
    int64_t createdAt;
    
    nlohmann::json ToJson() const;
    static EternityCelestial FromJson(const nlohmann::json& j);
};

struct CosmosCelestial {
    std::string cosmosId;
    std::string name;
    float cosmos;          // 0.0 to 1.0
    float celestialness;   // 0.0 to 1.0
    float universe;    // 0.0 to 1.0
    float expanse;     // 0.0 to 1.0
    int64_t createdAt;
    
    nlohmann::json ToJson() const;
    static CosmosCelestial FromJson(const nlohmann::json& j);
};

struct FirmamentCelestial {
    std::string firmamentId;
    std::string name;
    float firmament;       // 0.0 to 1.0
    float celestialness;   // 0.0 to 1.0
    float vault;       // 0.0 to 1.0
    float canopy;      // 0.0 to 1.0
    bool isVaulted;
    int64_t createdAt;
    
    nlohmann::json ToJson() const;
    static FirmamentCelestial FromJson(const nlohmann::json& j);
};

struct AetherCelestial {
    std::string aetherId;
    std::string name;
    float aether;          // 0.0 to 1.0
    float celestialness;   // 0.0 to 1.0
    float quintessence; // 0.0 to 1.0
    float essence;      // 0.0 to 1.0
    int64_t createdAt;
    
    nlohmann::json ToJson() const;
    static AetherCelestial FromJson(const nlohmann::json& j);
};

// Core engine class
class CelestialEternityEngine {
public:
    // Initialization
    static void Init();
    static void Shutdown();
    static bool IsInitialized();
    
    // Celestial Eternity Structure operations
    static std::string CreateCelestialEternityStructure(const std::string& name);
    static bool DestroyCelestialEternityStructure(const std::string& celestialId);
    static std::shared_ptr<CelestialEternityStructure> GetCelestialEternityStructure(const std::string& celestialId);
    static std::vector<CelestialEternityStructure> GetAllCelestialEternityStructures();
    static bool ElevateCelestialness(const std::string& celestialId, float amount);
    static bool ExpandEternity(const std::string& celestialId, float amount);
    static bool UnfoldCosmos(const std::string& celestialId, float amount);
    static bool RaiseFirmament(const std::string& celestialId, float amount);
    static bool RefineAether(const std::string& celestialId, float amount);
    
    // Eternity Celestial operations
    static std::string CreateEternityCelestial(const std::string& name);
    static bool DestroyEternityCelestial(const std::string& eternityId);
    static std::shared_ptr<EternityCelestial> GetEternityCelestial(const std::string& eternityId);
    static std::vector<EternityCelestial> GetAllEternityCelestials();
    static bool ExtendInfinity(const std::string& eternityId, float amount);
    static bool EnsurePerpetuity(const std::string& eternityId, float amount);
    static bool DeclareEternal(const std::string& eternityId);
    
    // Cosmos Celestial operations
    static std::string CreateCosmosCelestial(const std::string& name);
    static bool DestroyCosmosCelestial(const std::string& cosmosId);
    static std::shared_ptr<CosmosCelestial> GetCosmosCelestial(const std::string& cosmosId);
    static std::vector<CosmosCelestial> GetAllCosmosCelestials();
    static bool ExpandUniverse(const std::string& cosmosId, float amount);
    static bool WidenExpanse(const std::string& cosmosId, float amount);
    
    // Firmament Celestial operations
    static std::string CreateFirmamentCelestial(const std::string& name);
    static bool DestroyFirmamentCelestial(const std::string& firmamentId);
    static std::shared_ptr<FirmamentCelestial> GetFirmamentCelestial(const std::string& firmamentId);
    static std::vector<FirmamentCelestial> GetAllFirmamentCelestials();
    static bool FortifyVault(const std::string& firmamentId, float amount);
    static bool ExtendCanopy(const std::string& firmamentId, float amount);
    static bool DeclareVaulted(const std::string& firmamentId);
    
    // Aether Celestial operations
    static std::string CreateAetherCelestial(const std::string& name);
    static bool DestroyAetherCelestial(const std::string& aetherId);
    static std::shared_ptr<AetherCelestial> GetAetherCelestial(const std::string& aetherId);
    static std::vector<AetherCelestial> GetAllAetherCelestials();
    static bool DistillQuintessence(const std::string& aetherId, float amount);
    static bool PurifyEssence(const std::string& aetherId, float amount);
    
    // Metrics and reporting
    static nlohmann::json GetCelestialEternityMetrics();
    static nlohmann::json GenerateCelestialEternityReport();
    
private:
    static bool s_initialized;
    static std::mutex s_celestialMutex;
    static std::mutex s_eternityMutex;
    static std::mutex s_cosmosMutex;
    static std::mutex s_firmamentMutex;
    static std::mutex s_aetherMutex;
    
    static std::vector<std::shared_ptr<CelestialEternityStructure>> s_celestialStructures;
    static std::vector<std::shared_ptr<EternityCelestial>> s_eternityCelestials;
    static std::vector<std::shared_ptr<CosmosCelestial>> s_cosmosCelestials;
    static std::vector<std::shared_ptr<FirmamentCelestial>> s_firmamentCelestials;
    static std::vector<std::shared_ptr<AetherCelestial>> s_aetherCelestials;
    
    static std::atomic<int64_t> s_celestialCounter;
    static std::atomic<int64_t> s_eternityCounter;
    static std::atomic<int64_t> s_cosmosCounter;
    static std::atomic<int64_t> s_firmamentCounter;
    static std::atomic<int64_t> s_aetherCounter;
};

} // namespace CelestialEternity
