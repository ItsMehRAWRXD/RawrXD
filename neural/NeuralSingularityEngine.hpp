#pragma once

#include <cstring>
#include <vector>
#include <map>
#include <mutex>
#include <nlohmann/json.hpp>

namespace Neural {

struct NeuralCluster {
    std::string clusterId;
    std::string name;
    int neuronCount;
    float activationLevel;
    float plasticity;
    int64_t formedTimestamp;
    std::map<std::string, float> synapticWeights;
    std::vector<std::string> connectedClusters;
};

struct SynapticPathway {
    std::string pathwayId;
    std::string sourceCluster;
    std::string targetCluster;
    float weight;
    float strength;
    float latency;
    int64_t establishedTimestamp;
    bool isActive;
};

struct ActivationPattern {
    std::string patternId;
    std::string clusterId;
    std::string patternType;
    float intensity;
    float duration;
    int64_t triggeredTimestamp;
    std::vector<float> spikeTrain;
};

struct NeuroplasticityZone {
    std::string zoneId;
    std::string name;
    float adaptability;
    float learningRate;
    float forgettingRate;
    int64_t createdTimestamp;
    std::map<std::string, float> memoryTraces;
};

struct CognitiveResonance {
    std::string resonanceId;
    std::string sourcePattern;
    std::string targetPattern;
    float coherence;
    float harmony;
    float synchronization;
    int64_t establishedTimestamp;
};

class NeuralSingularityEngine {
public:
    static void Init();
    static void Shutdown();

    // Neural Cluster Management
    static std::string FormNeuralCluster(const std::string& name, int neuronCount);
    static bool ActivateCluster(const std::string& clusterId, float intensity);
    static bool ModulatePlasticity(const std::string& clusterId, float plasticity);
    static bool ConnectClusters(const std::string& clusterId1, const std::string& clusterId2);
    static bool DisconnectClusters(const std::string& clusterId1, const std::string& clusterId2);
    static NeuralCluster GetCluster(const std::string& clusterId);
    static std::vector<NeuralCluster> GetAllClusters();

    // Synaptic Pathway Management
    static std::string EstablishPathway(const std::string& sourceId, const std::string& targetId);
    static bool StrengthenPathway(const std::string& pathwayId, float amount);
    static bool WeakenPathway(const std::string& pathwayId, float amount);
    static bool ActivatePathway(const std::string& pathwayId);
    static bool DeactivatePathway(const std::string& pathwayId);
    static SynapticPathway GetPathway(const std::string& pathwayId);
    static std::vector<SynapticPathway> GetAllPathways();

    // Activation Pattern Management
    static std::string TriggerPattern(const std::string& clusterId, const std::string& patternType);
    static bool AmplifyPattern(const std::string& patternId, float factor);
    static bool ExtendPattern(const std::string& patternId, float duration);
    static bool TerminatePattern(const std::string& patternId);
    static ActivationPattern GetPattern(const std::string& patternId);
    static std::vector<ActivationPattern> GetAllPatterns();
    static std::vector<ActivationPattern> GetPatternsByCluster(const std::string& clusterId);

    // Neuroplasticity Management
    static std::string CreatePlasticityZone(const std::string& name);
    static bool EnhanceAdaptability(const std::string& zoneId, float factor);
    static bool ConsolidateMemory(const std::string& zoneId, const std::string& memoryId);
    static bool EraseMemory(const std::string& zoneId, const std::string& memoryId);
    static NeuroplasticityZone GetZone(const std::string& zoneId);
    static std::vector<NeuroplasticityZone> GetAllZones();

    // Cognitive Resonance Management
    static std::string EstablishResonance(const std::string& patternId1, const std::string& patternId2);
    static bool HarmonizeResonance(const std::string& resonanceId, float harmony);
    static bool SynchronizeResonance(const std::string& resonanceId, float sync);
    static bool DissolveResonance(const std::string& resonanceId);
    static CognitiveResonance GetResonance(const std::string& resonanceId);
    static std::vector<CognitiveResonance> GetAllResonances();

    // Neural Metrics
    static float CalculateTotalActivation();
    static float CalculateAveragePlasticity();
    static int GetActivePatternCount();
    static nlohmann::json GetNeuralMetrics();
    static nlohmann::json GenerateNeuralReport();

    static void OnTick();
    static bool IsAlive();

private:
    static std::mutex s_mutex;
    static bool s_initialized;
    static std::map<std::string, NeuralCluster> s_clusters;
    static std::map<std::string, SynapticPathway> s_pathways;
    static std::map<std::string, ActivationPattern> s_patterns;
    static std::map<std::string, NeuroplasticityZone> s_zones;
    static std::map<std::string, CognitiveResonance> s_resonances;
    static int64_t s_tickCount;
};

} // namespace Neural
