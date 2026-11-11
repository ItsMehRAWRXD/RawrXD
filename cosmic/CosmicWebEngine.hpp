#pragma once
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>

namespace Cosmic {

struct GalaxyCluster {
    std::string clusterId;
    std::string name;
    std::vector<std::string> galaxies;
    float cosmicPosition[3];
    float mass;
    float darkMatterRatio;
    float coherence;
    int64_t formedTimestamp;
};

struct CosmicFilament {
    std::string filamentId;
    std::string name;
    std::vector<std::string> galaxyClusters;
    float length;
    float density;
    std::map<std::string, float> energyFlows;
};

struct Supercluster {
    std::string superclusterId;
    std::string name;
    std::vector<std::string> filaments;
    float volume;
    float mass;
    std::map<std::string, nlohmann::json> properties;
};

struct CosmicWebNode {
    std::string nodeId;
    std::string type;
    float position[3];
    std::vector<std::string> connections;
    float influence;
    nlohmann::json metadata;
};

struct UniversalCouncil {
    std::string councilId;
    std::string name;
    std::vector<std::string> memberSuperclusters;
    std::map<std::string, float> cosmicVotingPower;
    nlohmann::json universalResolutions;
    int64_t lastConvenedTimestamp;
};

class CosmicWebEngine {
public:
    static void Init();
    static void Shutdown();
    
    static std::string FormGalaxyCluster(const std::string& name,
                                        const std::vector<std::string>& galaxies,
                                        const float position[3]);
    static bool DissolveGalaxyCluster(const std::string& clusterId);
    static GalaxyCluster GetGalaxyCluster(const std::string& clusterId);
    static std::vector<GalaxyCluster> GetAllGalaxyClusters();
    
    static std::string WeaveFilament(const std::string& name,
                                     const std::vector<std::string>& galaxyClusters);
    static CosmicFilament GetFilament(const std::string& filamentId);
    static std::vector<CosmicFilament> GetAllFilaments();
    static float CalculateFilamentEnergy(const std::string& filamentId);
    
    static std::string FormSupercluster(const std::string& name,
                                       const std::vector<std::string>& filaments);
    static Supercluster GetSupercluster(const std::string& superclusterId);
    static std::vector<Supercluster> GetAllSuperclusters();
    
    static std::string CreateCosmicNode(const std::string& type,
                                       const float position[3],
                                       const nlohmann::json& metadata);
    static std::vector<CosmicWebNode> GetCosmicNodes();
    static std::vector<CosmicWebNode> GetNodesByType(const std::string& type);
    
    static std::string ConveneUniversalCouncil(const std::string& name,
                                               const std::vector<std::string>& superclusters);
    static bool ProposeUniversalResolution(const std::string& councilId,
                                            const std::string& resolutionId,
                                            const nlohmann::json& resolution);
    static bool VoteOnUniversalResolution(const std::string& councilId,
                                           const std::string& resolutionId,
                                           const std::string& superclusterId,
                                           bool approve);
    static UniversalCouncil GetUniversalCouncil(const std::string& councilId);
    
    static float CalculateCosmicCoherence();
    static float CalculateCosmicExpansion();
    static nlohmann::json GetCosmicMetrics();
    static nlohmann::json GenerateCosmicReport();
    
    static void OnTick();
    static bool IsAlive();

private:
    static std::mutex s_mutex;
    static bool s_initialized;
    static std::map<std::string, GalaxyCluster> s_galaxyClusters;
    static std::map<std::string, CosmicFilament> s_filaments;
    static std::map<std::string, Supercluster> s_superclusters;
    static std::map<std::string, CosmicWebNode> s_cosmicNodes;
    static std::map<std::string, UniversalCouncil> s_universalCouncils;
    static int64_t s_tickCount;
    static float s_cosmicExpansionRate;
};

} // namespace Cosmic
