#pragma once
#include <cstring>
#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>

namespace Infinite {

struct UniversalFrontier {
    std::string frontierId;
    std::string name;
    std::string frontierType; // "exploration", "settlement", "research", "expansion"
    std::string parentUniverse;
    float expansionRate;
    float stabilityIndex;
    std::vector<std::string> discoveredRegions;
    int64_t establishedTimestamp;
};

struct CosmicBoundary {
    std::string boundaryId;
    std::string name;
    std::string boundaryType; // "physical", "energetic", "dimensional", "temporal"
    float boundaryStrength;
    float permeability;
    std::map<std::string, float> crossingPoints;
    int64_t detectedTimestamp;
};

struct MultiversalThreshold {
    std::string thresholdId;
    std::string name;
    std::string thresholdClass; // "dimensional", "temporal", "conceptual", "existential"
    std::vector<std::string> connectedUniverses;
    float transitionEnergy;
    float stabilityFactor;
    int64_t identifiedTimestamp;
};

struct TranscendentLimit {
    std::string limitId;
    std::string name;
    std::string limitCategory; // "knowledge", "power", "existence", "understanding"
    float currentValue;
    float maximumValue;
    float expansionProgress;
    int64_t discoveredTimestamp;
};

struct HorizonDiscovery {
    std::string discoveryId;
    std::string name;
    std::string discoveryType;
    std::string frontierId;
    nlohmann::json discoveryData;
    float significance;
    int64_t discoveredTimestamp;
};

class InfiniteHorizonEngine {
public:
    static void Init();
    static void Shutdown();
    
    static std::string EstablishUniversalFrontier(const std::string& name,
                                                  const std::string& frontierType,
                                                  const std::string& parentUniverse);
    static bool ExpandFrontier(const std::string& frontierId, const std::string& regionId);
    static bool StabilizeFrontier(const std::string& frontierId, float stabilityBoost);
    static bool SetExpansionRate(const std::string& frontierId, float rate);
    static UniversalFrontier GetFrontier(const std::string& frontierId);
    static std::vector<UniversalFrontier> GetAllFrontiers();
    static std::vector<UniversalFrontier> GetFrontiersByType(const std::string& frontierType);
    
    static std::string DetectCosmicBoundary(const std::string& name,
                                            const std::string& boundaryType,
                                            float strength);
    static bool ReinforceBoundary(const std::string& boundaryId, float strengthBoost);
    static bool AdjustPermeability(const std::string& boundaryId, float permeability);
    static bool RegisterCrossingPoint(const std::string& boundaryId, const std::string& pointId, float accessibility);
    static CosmicBoundary GetBoundary(const std::string& boundaryId);
    static std::vector<CosmicBoundary> GetAllBoundaries();
    static std::vector<CosmicBoundary> GetBoundariesByType(const std::string& boundaryType);
    
    static std::string IdentifyMultiversalThreshold(const std::string& name,
                                                    const std::string& thresholdClass,
                                                    const std::vector<std::string>& universes);
    static bool StabilizeThreshold(const std::string& thresholdId, float stabilityBoost);
    static bool AdjustTransitionEnergy(const std::string& thresholdId, float energy);
    static MultiversalThreshold GetThreshold(const std::string& thresholdId);
    static std::vector<MultiversalThreshold> GetAllThresholds();
    static std::vector<MultiversalThreshold> GetThresholdsByClass(const std::string& thresholdClass);
    
    static std::string DiscoverTranscendentLimit(const std::string& name,
                                                 const std::string& limitCategory,
                                                 float maximumValue);
    static bool ExpandLimit(const std::string& limitId, float expansion);
    static bool PushLimitBoundary(const std::string& limitId, float newMaximum);
    static TranscendentLimit GetLimit(const std::string& limitId);
    static std::vector<TranscendentLimit> GetAllLimits();
    static std::vector<TranscendentLimit> GetLimitsByCategory(const std::string& limitCategory);
    
    static std::string RecordHorizonDiscovery(const std::string& name,
                                              const std::string& discoveryType,
                                              const std::string& frontierId,
                                              const nlohmann::json& data,
                                              float significance);
    static HorizonDiscovery GetDiscovery(const std::string& discoveryId);
    static std::vector<HorizonDiscovery> GetAllDiscoveries();
    static std::vector<HorizonDiscovery> GetDiscoveriesByFrontier(const std::string& frontierId);
    
    static float CalculateTotalExpansion();
    static float CalculateBoundaryIntegrity();
    static nlohmann::json GetHorizonMetrics();
    static nlohmann::json GenerateHorizonReport();
    
    static void OnTick();
    static bool IsAlive();

private:
    static std::mutex s_mutex;
    static bool s_initialized;
    static std::map<std::string, UniversalFrontier> s_frontiers;
    static std::map<std::string, CosmicBoundary> s_boundaries;
    static std::map<std::string, MultiversalThreshold> s_thresholds;
    static std::map<std::string, TranscendentLimit> s_limits;
    static std::map<std::string, HorizonDiscovery> s_discoveries;
    static int64_t s_tickCount;
};

} // namespace Infinite
