#include "celestial/CelestialForgeEngine.hpp"
#include <chrono>
#include <algorithm>

namespace Celestial {

std::mutex CelestialForgeEngine::s_mutex;
bool CelestialForgeEngine::s_initialized = false;
std::map<std::string, UniversalConstructor> CelestialForgeEngine::s_constructors;
std::map<std::string, CosmicFabricator> CelestialForgeEngine::s_fabricators;
std::map<std::string, MultiversalSynthesizer> CelestialForgeEngine::s_synthesizers;
std::map<std::string, TranscendentCreationEngine> CelestialForgeEngine::s_engines;
std::map<std::string, CelestialArtifact> CelestialForgeEngine::s_artifacts;
int64_t CelestialForgeEngine::s_tickCount = 0;

void CelestialForgeEngine::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (s_initialized) return;
    s_initialized = true;
    s_tickCount = 0;
}

void CelestialForgeEngine::Shutdown() {
    std::lock_guard<std::mutex> lock(s_mutex);
    s_initialized = false;
    s_constructors.clear();
    s_fabricators.clear();
    s_synthesizers.clear();
    s_engines.clear();
    s_artifacts.clear();
}

std::string CelestialForgeEngine::CommissionUniversalConstructor(const std::string& name,
                                                                 const std::string& constructionType,
                                                                 float outputCapacity) {
    std::lock_guard<std::mutex> lock(s_mutex);
    static int constructorCounter = 0;
    std::string constructorId = "universal_constructor_" + std::to_string(++constructorCounter);
    
    UniversalConstructor constructor;
    constructor.constructorId = constructorId;
    constructor.name = name;
    constructor.constructionType = constructionType;
    constructor.outputCapacity = outputCapacity;
    constructor.efficiency = 1.0f;
    constructor.active = false;
    constructor.commissionedTimestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_constructors[constructorId] = constructor;
    return constructorId;
}

bool CelestialForgeEngine::ActivateConstructor(const std::string& constructorId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_constructors.find(constructorId);
    if (it == s_constructors.end()) return false;
    it->second.active = true;
    return true;
}

bool CelestialForgeEngine::DeactivateConstructor(const std::string& constructorId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_constructors.find(constructorId);
    if (it == s_constructors.end()) return false;
    it->second.active = false;
    return true;
}

bool CelestialForgeEngine::LoadBlueprint(const std::string& constructorId, const std::string& blueprint) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_constructors.find(constructorId);
    if (it == s_constructors.end()) return false;
    it->second.blueprints.push_back(blueprint);
    return true;
}

UniversalConstructor CelestialForgeEngine::GetConstructor(const std::string& constructorId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_constructors.find(constructorId);
    if (it != s_constructors.end()) return it->second;
    return UniversalConstructor{};
}

std::vector<UniversalConstructor> CelestialForgeEngine::GetAllConstructors() {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<UniversalConstructor> result;
    for (const auto& [id, constructor] : s_constructors) {
        result.push_back(constructor);
    }
    return result;
}

std::vector<UniversalConstructor> CelestialForgeEngine::GetActiveConstructors() {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<UniversalConstructor> result;
    for (const auto& [id, constructor] : s_constructors) {
        if (constructor.active) result.push_back(constructor);
    }
    return result;
}

std::string CelestialForgeEngine::DeployCosmicFabricator(const std::string& name,
                                                         const std::string& fabricationMethod) {
    std::lock_guard<std::mutex> lock(s_mutex);
    static int fabricatorCounter = 0;
    std::string fabricatorId = "cosmic_fabricator_" + std::to_string(++fabricatorCounter);
    
    CosmicFabricator fabricator;
    fabricator.fabricatorId = fabricatorId;
    fabricator.name = name;
    fabricator.fabricationMethod = fabricationMethod;
    fabricator.productionRate = 1.0f;
    fabricator.lastProductionTimestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_fabricators[fabricatorId] = fabricator;
    return fabricatorId;
}

bool CelestialForgeEngine::ConfigureFabricatorInputs(const std::string& fabricatorId, 
                                                     const std::map<std::string, float>& inputs) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_fabricators.find(fabricatorId);
    if (it == s_fabricators.end()) return false;
    it->second.resourceInputs = inputs;
    return true;
}

bool CelestialForgeEngine::StartFabrication(const std::string& fabricatorId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_fabricators.find(fabricatorId);
    if (it == s_fabricators.end()) return false;
    it->second.productionRate = 1.0f;
    return true;
}

bool CelestialForgeEngine::StopFabrication(const std::string& fabricatorId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_fabricators.find(fabricatorId);
    if (it == s_fabricators.end()) return false;
    it->second.productionRate = 0.0f;
    return true;
}

CosmicFabricator CelestialForgeEngine::GetFabricator(const std::string& fabricatorId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_fabricators.find(fabricatorId);
    if (it != s_fabricators.end()) return it->second;
    return CosmicFabricator{};
}

std::vector<CosmicFabricator> CelestialForgeEngine::GetAllFabricators() {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<CosmicFabricator> result;
    for (const auto& [id, fabricator] : s_fabricators) {
        result.push_back(fabricator);
    }
    return result;
}

std::string CelestialForgeEngine::EstablishMultiversalSynthesizer(const std::string& name,
                                                                  const std::string& synthesisType,
                                                                  const nlohmann::json& formula) {
    std::lock_guard<std::mutex> lock(s_mutex);
    static int synthesizerCounter = 0;
    std::string synthesizerId = "multiversal_synthesizer_" + std::to_string(++synthesizerCounter);
    
    MultiversalSynthesizer synthesizer;
    synthesizer.synthesizerId = synthesizerId;
    synthesizer.name = name;
    synthesizer.synthesisType = synthesisType;
    synthesizer.synthesisFormula = formula;
    synthesizer.purityLevel = 1.0f;
    synthesizer.yieldRate = 1.0f;
    synthesizer.establishedTimestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_synthesizers[synthesizerId] = synthesizer;
    return synthesizerId;
}

bool CelestialForgeEngine::UpdateSynthesisFormula(const std::string& synthesizerId, const nlohmann::json& formula) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_synthesizers.find(synthesizerId);
    if (it == s_synthesizers.end()) return false;
    it->second.synthesisFormula = formula;
    return true;
}

bool CelestialForgeEngine::RunSynthesis(const std::string& synthesizerId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_synthesizers.find(synthesizerId);
    if (it == s_synthesizers.end()) return false;
    it->second.yieldRate *= 0.99f;
    it->second.yieldRate += 0.01f;
    return true;
}

MultiversalSynthesizer CelestialForgeEngine::GetSynthesizer(const std::string& synthesizerId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_synthesizers.find(synthesizerId);
    if (it != s_synthesizers.end()) return it->second;
    return MultiversalSynthesizer{};
}

std::vector<MultiversalSynthesizer> CelestialForgeEngine::GetAllSynthesizers() {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<MultiversalSynthesizer> result;
    for (const auto& [id, synthesizer] : s_synthesizers) {
        result.push_back(synthesizer);
    }
    return result;
}

std::string CelestialForgeEngine::ActivateCreationEngine(const std::string& name,
                                                         const std::string& creationDomain,
                                                         float creationPower) {
    std::lock_guard<std::mutex> lock(s_mutex);
    static int engineCounter = 0;
    std::string engineId = "creation_engine_" + std::to_string(++engineCounter);
    
    TranscendentCreationEngine engine;
    engine.engineId = engineId;
    engine.name = name;
    engine.creationDomain = creationDomain;
    engine.creationPower = creationPower;
    engine.stabilityIndex = 1.0f;
    engine.activatedTimestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_engines[engineId] = engine;
    return engineId;
}

bool CelestialForgeEngine::LogCreation(const std::string& engineId, const std::string& creationDescription) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_engines.find(engineId);
    if (it == s_engines.end()) return false;
    it->second.creationLog.push_back(creationDescription);
    return true;
}

TranscendentCreationEngine CelestialForgeEngine::GetCreationEngine(const std::string& engineId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_engines.find(engineId);
    if (it != s_engines.end()) return it->second;
    return TranscendentCreationEngine{};
}

std::vector<TranscendentCreationEngine> CelestialForgeEngine::GetAllCreationEngines() {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<TranscendentCreationEngine> result;
    for (const auto& [id, engine] : s_engines) {
        result.push_back(engine);
    }
    return result;
}

std::string CelestialForgeEngine::ForgeCelestialArtifact(const std::string& name,
                                                         const std::string& artifactType,
                                                         const std::string& creatorId,
                                                         const nlohmann::json& properties) {
    std::lock_guard<std::mutex> lock(s_mutex);
    static int artifactCounter = 0;
    std::string artifactId = "celestial_artifact_" + std::to_string(++artifactCounter);
    
    CelestialArtifact artifact;
    artifact.artifactId = artifactId;
    artifact.name = name;
    artifact.artifactType = artifactType;
    artifact.creatorId = creatorId;
    artifact.properties = properties;
    artifact.powerLevel = 1.0f;
    artifact.createdTimestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_artifacts[artifactId] = artifact;
    return artifactId;
}

CelestialArtifact CelestialForgeEngine::GetArtifact(const std::string& artifactId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_artifacts.find(artifactId);
    if (it != s_artifacts.end()) return it->second;
    return CelestialArtifact{};
}

std::vector<CelestialArtifact> CelestialForgeEngine::GetAllArtifacts() {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<CelestialArtifact> result;
    for (const auto& [id, artifact] : s_artifacts) {
        result.push_back(artifact);
    }
    return result;
}

std::vector<CelestialArtifact> CelestialForgeEngine::GetArtifactsByCreator(const std::string& creatorId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<CelestialArtifact> result;
    for (const auto& [id, artifact] : s_artifacts) {
        if (artifact.creatorId == creatorId) result.push_back(artifact);
    }
    return result;
}

float CelestialForgeEngine::CalculateTotalProductionCapacity() {
    std::lock_guard<std::mutex> lock(s_mutex);
    float totalCapacity = 0.0f;
    for (const auto& [id, constructor] : s_constructors) {
        if (constructor.active) {
            totalCapacity += constructor.outputCapacity * constructor.efficiency;
        }
    }
    for (const auto& [id, fabricator] : s_fabricators) {
        totalCapacity += fabricator.productionRate;
    }
    return totalCapacity;
}

float CelestialForgeEngine::CalculateForgeEfficiency() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (s_constructors.empty()) return 1.0f;
    float totalEfficiency = 0.0f;
    int activeCount = 0;
    for (const auto& [id, constructor] : s_constructors) {
        if (constructor.active) {
            totalEfficiency += constructor.efficiency;
            activeCount++;
        }
    }
    return activeCount > 0 ? totalEfficiency / activeCount : 1.0f;
}

nlohmann::json CelestialForgeEngine::GetForgeMetrics() {
    std::lock_guard<std::mutex> lock(s_mutex);
    nlohmann::json metrics;
    metrics["constructorCount"] = s_constructors.size();
    metrics["activeConstructorCount"] = GetActiveConstructors().size();
    metrics["fabricatorCount"] = s_fabricators.size();
    metrics["synthesizerCount"] = s_synthesizers.size();
    metrics["creationEngineCount"] = s_engines.size();
    metrics["artifactCount"] = s_artifacts.size();
    metrics["totalProductionCapacity"] = CalculateTotalProductionCapacity();
    metrics["forgeEfficiency"] = CalculateForgeEfficiency();
    metrics["tickCount"] = s_tickCount;
    return metrics;
}

nlohmann::json CelestialForgeEngine::GenerateForgeReport() {
    nlohmann::json report;
    report["metrics"] = GetForgeMetrics();
    report["activeConstructors"] = nlohmann::json::array();
    report["recentArtifacts"] = nlohmann::json::array();
    report["creationEngines"] = nlohmann::json::array();
    
    for (const auto& constructor : GetActiveConstructors()) {
        nlohmann::json c;
        c["id"] = constructor.constructorId;
        c["name"] = constructor.name;
        c["type"] = constructor.constructionType;
        c["capacity"] = constructor.outputCapacity;
        report["activeConstructors"].push_back(c);
    }
    
    for (const auto& artifact : GetAllArtifacts()) {
        nlohmann::json a;
        a["id"] = artifact.artifactId;
        a["name"] = artifact.name;
        a["type"] = artifact.artifactType;
        a["power"] = artifact.powerLevel;
        report["recentArtifacts"].push_back(a);
    }
    
    return report;
}

void CelestialForgeEngine::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    s_tickCount++;
    
    for (auto& [id, constructor] : s_constructors) {
        if (constructor.active) {
            constructor.efficiency *= 0.9999f;
            constructor.efficiency += 0.0001f;
        }
    }
    
    for (auto& [id, fabricator] : s_fabricators) {
        if (fabricator.productionRate > 0) {
            for (auto& [resource, amount] : fabricator.resourceInputs) {
                amount *= 0.9999f;
            }
        }
    }
    
    for (auto& [id, synthesizer] : s_synthesizers) {
        synthesizer.purityLevel *= 0.9999f;
        synthesizer.purityLevel += 0.0001f;
    }
}

bool CelestialForgeEngine::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}

} // namespace Celestial
