#include "neural/NeuralSingularityEngine.hpp"
#include <chrono>
#include <algorithm>

namespace Neural {

std::mutex NeuralSingularityEngine::s_mutex;
bool NeuralSingularityEngine::s_initialized = false;
std::map<std::string, NeuralCluster> NeuralSingularityEngine::s_clusters;
std::map<std::string, SynapticPathway> NeuralSingularityEngine::s_pathways;
std::map<std::string, ActivationPattern> NeuralSingularityEngine::s_patterns;
std::map<std::string, NeuroplasticityZone> NeuralSingularityEngine::s_zones;
std::map<std::string, CognitiveResonance> NeuralSingularityEngine::s_resonances;
int64_t NeuralSingularityEngine::s_tickCount = 0;

void NeuralSingularityEngine::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (s_initialized) return;
    s_initialized = true;
    s_tickCount = 0;
}

void NeuralSingularityEngine::Shutdown() {
    std::lock_guard<std::mutex> lock(s_mutex);
    s_initialized = false;
    s_clusters.clear();
    s_pathways.clear();
    s_patterns.clear();
    s_zones.clear();
    s_resonances.clear();
}

std::string NeuralSingularityEngine::FormNeuralCluster(const std::string& name, int neuronCount) {
    std::lock_guard<std::mutex> lock(s_mutex);
    static int clusterCounter = 0;
    std::string clusterId = "neural_cluster_" + std::to_string(++clusterCounter);
    
    NeuralCluster cluster;
    cluster.clusterId = clusterId;
    cluster.name = name;
    cluster.neuronCount = neuronCount;
    cluster.activationLevel = 0.0f;
    cluster.plasticity = 0.5f;
    cluster.formedTimestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_clusters[clusterId] = cluster;
    return clusterId;
}

bool NeuralSingularityEngine::ActivateCluster(const std::string& clusterId, float intensity) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_clusters.find(clusterId);
    if (it == s_clusters.end()) return false;
    it->second.activationLevel = std::min(1.0f, it->second.activationLevel + intensity);
    return true;
}

bool NeuralSingularityEngine::ModulatePlasticity(const std::string& clusterId, float plasticity) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_clusters.find(clusterId);
    if (it == s_clusters.end()) return false;
    it->second.plasticity = std::max(0.0f, std::min(1.0f, plasticity));
    return true;
}

bool NeuralSingularityEngine::ConnectClusters(const std::string& clusterId1, const std::string& clusterId2) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it1 = s_clusters.find(clusterId1);
    auto it2 = s_clusters.find(clusterId2);
    if (it1 == s_clusters.end() || it2 == s_clusters.end()) return false;
    
    it1->second.connectedClusters.push_back(clusterId2);
    it2->second.connectedClusters.push_back(clusterId1);
    return true;
}

bool NeuralSingularityEngine::DisconnectClusters(const std::string& clusterId1, const std::string& clusterId2) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it1 = s_clusters.find(clusterId1);
    auto it2 = s_clusters.find(clusterId2);
    if (it1 == s_clusters.end() || it2 == s_clusters.end()) return false;
    
    auto& vec1 = it1->second.connectedClusters;
    auto& vec2 = it2->second.connectedClusters;
    vec1.erase(std::remove(vec1.begin(), vec1.end(), clusterId2), vec1.end());
    vec2.erase(std::remove(vec2.begin(), vec2.end(), clusterId1), vec2.end());
    return true;
}

NeuralCluster NeuralSingularityEngine::GetCluster(const std::string& clusterId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_clusters.find(clusterId);
    if (it != s_clusters.end()) return it->second;
    return NeuralCluster{};
}

std::vector<NeuralCluster> NeuralSingularityEngine::GetAllClusters() {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<NeuralCluster> result;
    for (const auto& [id, cluster] : s_clusters) {
        result.push_back(cluster);
    }
    return result;
}

std::string NeuralSingularityEngine::EstablishPathway(const std::string& sourceId, const std::string& targetId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    static int pathwayCounter = 0;
    std::string pathwayId = "synaptic_pathway_" + std::to_string(++pathwayCounter);
    
    SynapticPathway pathway;
    pathway.pathwayId = pathwayId;
    pathway.sourceCluster = sourceId;
    pathway.targetCluster = targetId;
    pathway.weight = 0.5f;
    pathway.strength = 0.5f;
    pathway.latency = 1.0f;
    pathway.establishedTimestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    pathway.isActive = true;
    
    s_pathways[pathwayId] = pathway;
    return pathwayId;
}

bool NeuralSingularityEngine::StrengthenPathway(const std::string& pathwayId, float amount) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_pathways.find(pathwayId);
    if (it == s_pathways.end()) return false;
    it->second.strength = std::min(1.0f, it->second.strength + amount);
    it->second.weight = it->second.strength;
    return true;
}

bool NeuralSingularityEngine::WeakenPathway(const std::string& pathwayId, float amount) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_pathways.find(pathwayId);
    if (it == s_pathways.end()) return false;
    it->second.strength = std::max(0.0f, it->second.strength - amount);
    it->second.weight = it->second.strength;
    return true;
}

bool NeuralSingularityEngine::ActivatePathway(const std::string& pathwayId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_pathways.find(pathwayId);
    if (it == s_pathways.end()) return false;
    it->second.isActive = true;
    return true;
}

bool NeuralSingularityEngine::DeactivatePathway(const std::string& pathwayId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_pathways.find(pathwayId);
    if (it == s_pathways.end()) return false;
    it->second.isActive = false;
    return true;
}

SynapticPathway NeuralSingularityEngine::GetPathway(const std::string& pathwayId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_pathways.find(pathwayId);
    if (it != s_pathways.end()) return it->second;
    return SynapticPathway{};
}

std::vector<SynapticPathway> NeuralSingularityEngine::GetAllPathways() {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<SynapticPathway> result;
    for (const auto& [id, pathway] : s_pathways) {
        result.push_back(pathway);
    }
    return result;
}

std::string NeuralSingularityEngine::TriggerPattern(const std::string& clusterId, const std::string& patternType) {
    std::lock_guard<std::mutex> lock(s_mutex);
    static int patternCounter = 0;
    std::string patternId = "activation_pattern_" + std::to_string(++patternCounter);
    
    ActivationPattern pattern;
    pattern.patternId = patternId;
    pattern.clusterId = clusterId;
    pattern.patternType = patternType;
    pattern.intensity = 0.5f;
    pattern.duration = 100.0f;
    pattern.triggeredTimestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_patterns[patternId] = pattern;
    return patternId;
}

bool NeuralSingularityEngine::AmplifyPattern(const std::string& patternId, float factor) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_patterns.find(patternId);
    if (it == s_patterns.end()) return false;
    it->second.intensity = std::min(1.0f, it->second.intensity * factor);
    return true;
}

bool NeuralSingularityEngine::ExtendPattern(const std::string& patternId, float duration) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_patterns.find(patternId);
    if (it == s_patterns.end()) return false;
    it->second.duration += duration;
    return true;
}

bool NeuralSingularityEngine::TerminatePattern(const std::string& patternId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_patterns.erase(patternId) > 0;
}

ActivationPattern NeuralSingularityEngine::GetPattern(const std::string& patternId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_patterns.find(patternId);
    if (it != s_patterns.end()) return it->second;
    return ActivationPattern{};
}

std::vector<ActivationPattern> NeuralSingularityEngine::GetAllPatterns() {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<ActivationPattern> result;
    for (const auto& [id, pattern] : s_patterns) {
        result.push_back(pattern);
    }
    return result;
}

std::vector<ActivationPattern> NeuralSingularityEngine::GetPatternsByCluster(const std::string& clusterId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<ActivationPattern> result;
    for (const auto& [id, pattern] : s_patterns) {
        if (pattern.clusterId == clusterId) result.push_back(pattern);
    }
    return result;
}

std::string NeuralSingularityEngine::CreatePlasticityZone(const std::string& name) {
    std::lock_guard<std::mutex> lock(s_mutex);
    static int zoneCounter = 0;
    std::string zoneId = "plasticity_zone_" + std::to_string(++zoneCounter);
    
    NeuroplasticityZone zone;
    zone.zoneId = zoneId;
    zone.name = name;
    zone.adaptability = 0.5f;
    zone.learningRate = 0.1f;
    zone.forgettingRate = 0.01f;
    zone.createdTimestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_zones[zoneId] = zone;
    return zoneId;
}

bool NeuralSingularityEngine::EnhanceAdaptability(const std::string& zoneId, float factor) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_zones.find(zoneId);
    if (it == s_zones.end()) return false;
    it->second.adaptability = std::min(1.0f, it->second.adaptability * factor);
    return true;
}

bool NeuralSingularityEngine::ConsolidateMemory(const std::string& zoneId, const std::string& memoryId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_zones.find(zoneId);
    if (it == s_zones.end()) return false;
    it->second.memoryTraces[memoryId] = 1.0f;
    return true;
}

bool NeuralSingularityEngine::EraseMemory(const std::string& zoneId, const std::string& memoryId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_zones.find(zoneId);
    if (it == s_zones.end()) return false;
    return it->second.memoryTraces.erase(memoryId) > 0;
}

NeuroplasticityZone NeuralSingularityEngine::GetZone(const std::string& zoneId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_zones.find(zoneId);
    if (it != s_zones.end()) return it->second;
    return NeuroplasticityZone{};
}

std::vector<NeuroplasticityZone> NeuralSingularityEngine::GetAllZones() {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<NeuroplasticityZone> result;
    for (const auto& [id, zone] : s_zones) {
        result.push_back(zone);
    }
    return result;
}

std::string NeuralSingularityEngine::EstablishResonance(const std::string& patternId1, const std::string& patternId2) {
    std::lock_guard<std::mutex> lock(s_mutex);
    static int resonanceCounter = 0;
    std::string resonanceId = "cognitive_resonance_" + std::to_string(++resonanceCounter);
    
    CognitiveResonance resonance;
    resonance.resonanceId = resonanceId;
    resonance.sourcePattern = patternId1;
    resonance.targetPattern = patternId2;
    resonance.coherence = 0.5f;
    resonance.harmony = 0.5f;
    resonance.synchronization = 0.5f;
    resonance.establishedTimestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_resonances[resonanceId] = resonance;
    return resonanceId;
}

bool NeuralSingularityEngine::HarmonizeResonance(const std::string& resonanceId, float harmony) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_resonances.find(resonanceId);
    if (it == s_resonances.end()) return false;
    it->second.harmony = std::max(0.0f, std::min(1.0f, harmony));
    return true;
}

bool NeuralSingularityEngine::SynchronizeResonance(const std::string& resonanceId, float sync) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_resonances.find(resonanceId);
    if (it == s_resonances.end()) return false;
    it->second.synchronization = std::max(0.0f, std::min(1.0f, sync));
    return true;
}

bool NeuralSingularityEngine::DissolveResonance(const std::string& resonanceId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_resonances.erase(resonanceId) > 0;
}

CognitiveResonance NeuralSingularityEngine::GetResonance(const std::string& resonanceId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_resonances.find(resonanceId);
    if (it != s_resonances.end()) return it->second;
    return CognitiveResonance{};
}

std::vector<CognitiveResonance> NeuralSingularityEngine::GetAllResonances() {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<CognitiveResonance> result;
    for (const auto& [id, resonance] : s_resonances) {
        result.push_back(resonance);
    }
    return result;
}

float NeuralSingularityEngine::CalculateTotalActivation() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (s_clusters.empty()) return 0.0f;
    float total = 0.0f;
    for (const auto& [id, cluster] : s_clusters) {
        total += cluster.activationLevel;
    }
    return total / s_clusters.size();
}

float NeuralSingularityEngine::CalculateAveragePlasticity() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (s_clusters.empty()) return 0.0f;
    float total = 0.0f;
    for (const auto& [id, cluster] : s_clusters) {
        total += cluster.plasticity;
    }
    return total / s_clusters.size();
}

int NeuralSingularityEngine::GetActivePatternCount() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return static_cast<int>(s_patterns.size());
}

nlohmann::json NeuralSingularityEngine::GetNeuralMetrics() {
    std::lock_guard<std::mutex> lock(s_mutex);
    nlohmann::json metrics;
    metrics["clusterCount"] = s_clusters.size();
    metrics["pathwayCount"] = s_pathways.size();
    metrics["patternCount"] = s_patterns.size();
    metrics["zoneCount"] = s_zones.size();
    metrics["resonanceCount"] = s_resonances.size();
    metrics["totalActivation"] = CalculateTotalActivation();
    metrics["averagePlasticity"] = CalculateAveragePlasticity();
    metrics["activePatterns"] = GetActivePatternCount();
    metrics["tickCount"] = s_tickCount;
    return metrics;
}

nlohmann::json NeuralSingularityEngine::GenerateNeuralReport() {
    nlohmann::json report;
    report["metrics"] = GetNeuralMetrics();
    report["neuralClusters"] = nlohmann::json::array();
    report["synapticPathways"] = nlohmann::json::array();
    report["activationPatterns"] = nlohmann::json::array();
    
    for (const auto& cluster : GetAllClusters()) {
        nlohmann::json c;
        c["id"] = cluster.clusterId;
        c["name"] = cluster.name;
        c["neuronCount"] = cluster.neuronCount;
        c["activationLevel"] = cluster.activationLevel;
        c["plasticity"] = cluster.plasticity;
        report["neuralClusters"].push_back(c);
    }
    
    return report;
}

void NeuralSingularityEngine::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    s_tickCount++;
    
    for (auto& [id, cluster] : s_clusters) {
        if (cluster.activationLevel > 0.0f) {
            cluster.activationLevel *= 0.999f;
        }
    }
    
    for (auto& [id, pattern] : s_patterns) {
        if (pattern.duration > 0) {
            pattern.duration -= 1.0f;
        }
    }
}

bool NeuralSingularityEngine::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}

} // namespace Neural
