#pragma once
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>

namespace Galaxy {

struct StarCluster {
    std::string clusterId;
    std::string name;
    std::vector<std::string> starSystems;
    std::map<std::string, float> influenceMap;
    float galacticPosition[3];
    float coherence;
    float stability;
    int64_t formedTimestamp;
};

struct GalacticSpiralArm {
    std::string armId;
    std::string name;
    std::vector<std::string> starClusters;
    float density;
    float rotationVelocity;
    std::map<std::string, float> resourceFlows;
};

struct GalacticCore {
    std::string coreId;
    float mass;
    float luminosity;
    std::vector<std::string> governingClusters;
    std::map<std::string, nlohmann::json> corePolicies;
    float gravitationalInfluence;
};

struct InterstellarTradeRoute {
    std::string routeId;
    std::string sourceCluster;
    std::string targetCluster;
    float tradeVolume;
    std::vector<std::string> waypoints;
    float efficiency;
    bool active;
};

struct GalacticCouncil {
    std::string councilId;
    std::string name;
    std::vector<std::string> memberClusters;
    std::map<std::string, float> votingPower;
    nlohmann::json resolutions;
    int64_t lastSessionTimestamp;
};

class GalacticCoreEngine {
public:
    static void Init();
    static void Shutdown();
    
    static std::string FormStarCluster(const std::string& name, 
                                       const std::vector<std::string>& starSystems,
                                       const float position[3]);
    static bool DissolveStarCluster(const std::string& clusterId);
    static StarCluster GetStarCluster(const std::string& clusterId);
    static std::vector<StarCluster> GetAllStarClusters();
    
    static std::string DefineSpiralArm(const std::string& name,
                                        const std::vector<std::string>& starClusters);
    static GalacticSpiralArm GetSpiralArm(const std::string& armId);
    static std::vector<GalacticSpiralArm> GetAllSpiralArms();
    
    static void InitializeGalacticCore();
    static GalacticCore GetGalacticCore();
    static void UpdateCorePolicy(const std::string& policyId, const nlohmann::json& policy);
    
    static std::string EstablishTradeRoute(const std::string& sourceCluster,
                                            const std::string& targetCluster);
    static bool DissolveTradeRoute(const std::string& routeId);
    static std::vector<InterstellarTradeRoute> GetTradeRoutes();
    static float CalculateTradeVolume(const std::string& clusterId);
    
    static std::string ConveneGalacticCouncil(const std::string& name,
                                               const std::vector<std::string>& memberClusters);
    static bool ProposeResolution(const std::string& councilId, 
                                  const std::string& resolutionId,
                                  const nlohmann::json& resolution);
    static bool VoteOnResolution(const std::string& councilId,
                                 const std::string& resolutionId,
                                 const std::string& clusterId,
                                 bool approve);
    static GalacticCouncil GetCouncil(const std::string& councilId);
    
    static float CalculateGalacticCoherence();
    static float CalculateGalacticStability();
    static nlohmann::json GetGalacticMetrics();
    static nlohmann::json GenerateGalacticReport();
    
    static void OnTick();
    static bool IsAlive();

private:
    static std::mutex s_mutex;
    static bool s_initialized;
    static std::map<std::string, StarCluster> s_clusters;
    static std::map<std::string, GalacticSpiralArm> s_spiralArms;
    static std::unique_ptr<GalacticCore> s_galacticCore;
    static std::map<std::string, InterstellarTradeRoute> s_tradeRoutes;
    static std::map<std::string, GalacticCouncil> s_councils;
    static int64_t s_tickCount;
};

} // namespace Galaxy
