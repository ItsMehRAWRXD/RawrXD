#pragma once
#include <cstring>
#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>

namespace Celestial {

struct UniversalConstructor {
    std::string constructorId;
    std::string name;
    std::string constructionType; // "matter", "energy", "space", "time"
    float outputCapacity;
    float efficiency;
    std::vector<std::string> blueprints;
    bool active;
    int64_t commissionedTimestamp;
};

struct CosmicFabricator {
    std::string fabricatorId;
    std::string name;
    std::string fabricationMethod; // "synthesis", "transmutation", "assembly", "generation"
    std::map<std::string, float> resourceInputs;
    std::map<std::string, float> productOutputs;
    float productionRate;
    int64_t lastProductionTimestamp;
};

struct MultiversalSynthesizer {
    std::string synthesizerId;
    std::string name;
    std::string synthesisType; // "element", "compound", "structure", "entity"
    nlohmann::json synthesisFormula;
    float purityLevel;
    float yieldRate;
    int64_t establishedTimestamp;
};

struct TranscendentCreationEngine {
    std::string engineId;
    std::string name;
    std::string creationDomain; // "physical", "energetic", "dimensional", "conceptual"
    float creationPower;
    float stabilityIndex;
    std::vector<std::string> creationLog;
    int64_t activatedTimestamp;
};

struct CelestialArtifact {
    std::string artifactId;
    std::string name;
    std::string artifactType;
    std::string creatorId;
    nlohmann::json properties;
    float powerLevel;
    int64_t createdTimestamp;
};

class CelestialForgeEngine {
public:
    static void Init();
    static void Shutdown();
    
    static std::string CommissionUniversalConstructor(const std::string& name,
                                                    const std::string& constructionType,
                                                    float outputCapacity);
    static bool ActivateConstructor(const std::string& constructorId);
    static bool DeactivateConstructor(const std::string& constructorId);
    static bool LoadBlueprint(const std::string& constructorId, const std::string& blueprint);
    static UniversalConstructor GetConstructor(const std::string& constructorId);
    static std::vector<UniversalConstructor> GetAllConstructors();
    static std::vector<UniversalConstructor> GetActiveConstructors();
    
    static std::string DeployCosmicFabricator(const std::string& name,
                                              const std::string& fabricationMethod);
    static bool ConfigureFabricatorInputs(const std::string& fabricatorId, 
                                          const std::map<std::string, float>& inputs);
    static bool StartFabrication(const std::string& fabricatorId);
    static bool StopFabrication(const std::string& fabricatorId);
    static CosmicFabricator GetFabricator(const std::string& fabricatorId);
    static std::vector<CosmicFabricator> GetAllFabricators();
    
    static std::string EstablishMultiversalSynthesizer(const std::string& name,
                                                       const std::string& synthesisType,
                                                       const nlohmann::json& formula);
    static bool UpdateSynthesisFormula(const std::string& synthesizerId, const nlohmann::json& formula);
    static bool RunSynthesis(const std::string& synthesizerId);
    static MultiversalSynthesizer GetSynthesizer(const std::string& synthesizerId);
    static std::vector<MultiversalSynthesizer> GetAllSynthesizers();
    
    static std::string ActivateCreationEngine(const std::string& name,
                                              const std::string& creationDomain,
                                              float creationPower);
    static bool LogCreation(const std::string& engineId, const std::string& creationDescription);
    static TranscendentCreationEngine GetCreationEngine(const std::string& engineId);
    static std::vector<TranscendentCreationEngine> GetAllCreationEngines();
    
    static std::string ForgeCelestialArtifact(const std::string& name,
                                            const std::string& artifactType,
                                            const std::string& creatorId,
                                            const nlohmann::json& properties);
    static CelestialArtifact GetArtifact(const std::string& artifactId);
    static std::vector<CelestialArtifact> GetAllArtifacts();
    static std::vector<CelestialArtifact> GetArtifactsByCreator(const std::string& creatorId);
    
    static float CalculateTotalProductionCapacity();
    static float CalculateForgeEfficiency();
    static nlohmann::json GetForgeMetrics();
    static nlohmann::json GenerateForgeReport();
    
    static void OnTick();
    static bool IsAlive();

private:
    static std::mutex s_mutex;
    static bool s_initialized;
    static std::map<std::string, UniversalConstructor> s_constructors;
    static std::map<std::string, CosmicFabricator> s_fabricators;
    static std::map<std::string, MultiversalSynthesizer> s_synthesizers;
    static std::map<std::string, TranscendentCreationEngine> s_engines;
    static std::map<std::string, CelestialArtifact> s_artifacts;
    static int64_t s_tickCount;
};

} // namespace Celestial
