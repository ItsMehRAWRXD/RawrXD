#include "galaxy/GalacticCoreEngine.hpp"
#include <chrono>
#include <algorithm>

namespace Galaxy {

std::mutex GalacticCoreEngine::s_mutex;
bool GalacticCoreEngine::s_initialized = false;
std::map<std::string, StarCluster> GalacticCoreEngine::s_clusters;
std::map<std::string, GalacticSpiralArm> GalacticCoreEngine::s_spiralArms;
std::unique_ptr<GalacticCore> GalacticCoreEngine::s_galacticCore;
std::map<std::string, InterstellarTradeRoute> GalacticCoreEngine::s_tradeRoutes;
std::map<std::string, GalacticCouncil> GalacticCoreEngine::s_councils;
int64_t GalacticCoreEngine::s_tickCount = 0;

void GalacticCoreEngine::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (s_initialized) return;
    
    s_initialized = true;
    s_tickCount = 0;
    
    InitializeGalacticCore();
}

void GalacticCoreEngine::Shutdown() {
    std::lock_guard<std::mutex> lock(s_mutex);
    s_initialized = false;
    s_clusters.clear();
    s_spiralArms.clear();
    s_tradeRoutes.clear();
    s_councils.clear();
    s_galacticCore.reset();
}

std::string GalacticCoreEngine::FormStarCluster(const std::string& name,
                                               const std::vector<std::string>& starSystems,
                                               const float position[3]) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    static int clusterCounter = 0;
    std::string clusterId = "cluster_" + std::to_string(++clusterCounter);
    
    StarCluster cluster;
    cluster.clusterId = clusterId;
    cluster.name = name;
    cluster.starSystems = starSystems;
    cluster.galacticPosition[0] = position[0];
    cluster.galacticPosition[1] = position[1];
    cluster.galacticPosition[2] = position[2];
    cluster.coherence = 1.0f;
    cluster.stability = 1.0f;
    cluster.formedTimestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_clusters[clusterId] = cluster;
    return clusterId;
}

bool GalacticCoreEngine::DissolveStarCluster(const std::string& clusterId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    auto it = s_clusters.find(clusterId);
    if (it == s_clusters.end()) return false;
    
    s_clusters.erase(it);
    return true;
}

StarCluster GalacticCoreEngine::GetStarCluster(const std::string& clusterId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    auto it = s_clusters.find(clusterId);
    if (it != s_clusters.end()) return it->second;
    return StarCluster{};
}

std::vector<StarCluster> GalacticCoreEngine::GetAllStarClusters() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    std::vector<StarCluster> result;
    for (const auto& [id, cluster] : s_clusters) {
        result.push_back(cluster);
    }
    return result;
}

std::string GalacticCoreEngine::DefineSpiralArm(const std::string& name,
                                                const std::vector<std::string>& starClusters) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    static int armCounter = 0;
    std::string armId = "arm_" + std::to_string(++armCounter);
    
    GalacticSpiralArm arm;
    arm.armId = armId;
    arm.name = name;
    arm.starClusters = starClusters;
    arm.density = static_cast<float>(starClusters.size()) / 10.0f;
    arm.rotationVelocity = 200.0f + (rand() % 100);
    
    s_spiralArms[armId] = arm;
    return armId;
}

GalacticSpiralArm GalacticCoreEngine::GetSpiralArm(const std::string& armId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    auto it = s_spiralArms.find(armId);
    if (it != s_spiralArms.end()) return it->second;
    return GalacticSpiralArm{};
}

std::vector<GalacticSpiralArm> GalacticCoreEngine::GetAllSpiralArms() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    std::vector<GalacticSpiralArm> result;
    for (const auto& [id, arm] : s_spiralArms) {
        result.push_back(arm);
    }
    return result;
}

void GalacticCoreEngine::InitializeGalacticCore() {
    s_galacticCore = std::make_unique<GalacticCore>();
    s_galacticCore->coreId = "galactic_core_001";
    s_galacticCore->mass = 1.0e6f;
    s_galacticCore->luminosity = 1.0e9f;
    s_galacticCore->gravitationalInfluence = 1.0f;
}

GalacticCore GalacticCoreEngine::GetGalacticCore() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    if (s_galacticCore) return *s_galacticCore;
    return GalacticCore{};
}

void GalacticCoreEngine::UpdateCorePolicy(const std::string& policyId, const nlohmann::json& policy) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    if (s_galacticCore) {
        s_galacticCore->corePolicies[policyId] = policy;
    }
}

std::string GalacticCoreEngine::EstablishTradeRoute(const std::string& sourceCluster,
                                                    const std::string& targetCluster) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    static int routeCounter = 0;
    std::string routeId = "route_" + std::to_string(++routeCounter);
    
    InterstellarTradeRoute route;
    route.routeId = routeId;
    route.sourceCluster = sourceCluster;
    route.targetCluster = targetCluster;
    route.tradeVolume = 0.0f;
    route.efficiency = 1.0f;
    route.active = true;
    
    s_tradeRoutes[routeId] = route;
    return routeId;
}

bool GalacticCoreEngine::DissolveTradeRoute(const std::string& routeId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    auto it = s_tradeRoutes.find(routeId);
    if (it == s_tradeRoutes.end()) return false;
    
    s_tradeRoutes.erase(it);
    return true;
}

std::vector<InterstellarTradeRoute> GalacticCoreEngine::GetTradeRoutes() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    std::vector<InterstellarTradeRoute> result;
    for (const auto& [id, route] : s_tradeRoutes) {
        result.push_back(route);
    }
    return result;
}

float GalacticCoreEngine::CalculateTradeVolume(const std::string& clusterId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    float totalVolume = 0.0f;
    for (const auto& [id, route] : s_tradeRoutes) {
        if (route.sourceCluster == clusterId || route.targetCluster == clusterId) {
            totalVolume += route.tradeVolume;
        }
    }
    return totalVolume;
}

std::string GalacticCoreEngine::ConveneGalacticCouncil(const std::string& name,
                                                        const std::vector<std::string>& memberClusters) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    static int councilCounter = 0;
    std::string councilId = "council_" + std::to_string(++councilCounter);
    
    GalacticCouncil council;
    council.councilId = councilId;
    council.name = name;
    council.memberClusters = memberClusters;
    
    float equalPower = 1.0f / memberClusters.size();
    for (const auto& cluster : memberClusters) {
        council.votingPower[cluster] = equalPower;
    }
    
    council.lastSessionTimestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_councils[councilId] = council;
    return councilId;
}

bool GalacticCoreEngine::ProposeResolution(const std::string& councilId,
                                          const std::string& resolutionId,
                                          const nlohmann::json& resolution) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    auto it = s_councils.find(councilId);
    if (it == s_councils.end()) return false;
    
    it->second.resolutions[resolutionId] = resolution;
    return true;
}

bool GalacticCoreEngine::VoteOnResolution(const std::string& councilId,
                                         const std::string& resolutionId,
                                         const std::string& clusterId,
                                         bool approve) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    auto it = s_councils.find(councilId);
    if (it == s_councils.end()) return false;
    
    auto resIt = it->second.resolutions.find(resolutionId);
    if (resIt == it->second.resolutions.end()) return false;
    
    resIt->second["votes"][clusterId] = approve;
    return true;
}

GalacticCouncil GalacticCoreEngine::GetCouncil(const std::string& councilId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    auto it = s_councils.find(councilId);
    if (it != s_councils.end()) return it->second;
    return GalacticCouncil{};
}

float GalacticCoreEngine::CalculateGalacticCoherence() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    if (s_clusters.empty()) return 1.0f;
    
    float totalCoherence = 0.0f;
    for (const auto& [id, cluster] : s_clusters) {
        totalCoherence += cluster.coherence;
    }
    return totalCoherence / s_clusters.size();
}

float GalacticCoreEngine::CalculateGalacticStability() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    if (s_clusters.empty()) return 1.0f;
    
    float totalStability = 0.0f;
    for (const auto& [id, cluster] : s_clusters) {
        totalStability += cluster.stability;
    }
    return totalStability / s_clusters.size();
}

nlohmann::json GalacticCoreEngine::GetGalacticMetrics() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    nlohmann::json metrics;
    metrics["starClusterCount"] = s_clusters.size();
    metrics["spiralArmCount"] = s_spiralArms.size();
    metrics["tradeRouteCount"] = s_tradeRoutes.size();
    metrics["councilCount"] = s_councils.size();
    metrics["galacticCoherence"] = CalculateGalacticCoherence();
    metrics["galacticStability"] = CalculateGalacticStability();
    metrics["tickCount"] = s_tickCount;
    return metrics;
}

nlohmann::json GalacticCoreEngine::GenerateGalacticReport() {
    nlohmann::json report;
    report["metrics"] = GetGalacticMetrics();
    report["starClusters"] = nlohmann::json::array();
    report["spiralArms"] = nlohmann::json::array();
    report["tradeRoutes"] = nlohmann::json::array();
    report["councils"] = nlohmann::json::array();
    
    for (const auto& cluster : GetAllStarClusters()) {
        nlohmann::json c;
        c["id"] = cluster.clusterId;
        c["name"] = cluster.name;
        c["starSystemCount"] = cluster.starSystems.size();
        c["coherence"] = cluster.coherence;
        c["stability"] = cluster.stability;
        report["starClusters"].push_back(c);
    }
    
    for (const auto& arm : GetAllSpiralArms()) {
        nlohmann::json a;
        a["id"] = arm.armId;
        a["name"] = arm.name;
        a["clusterCount"] = arm.starClusters.size();
        a["density"] = arm.density;
        report["spiralArms"].push_back(a);
    }
    
    return report;
}

void GalacticCoreEngine::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    s_tickCount++;
    
    for (auto& [id, cluster] : s_clusters) {
        cluster.coherence *= 0.9999f;
        cluster.coherence += 0.0001f;
        cluster.stability *= 0.9999f;
        cluster.stability += 0.0001f;
    }
}

bool GalacticCoreEngine::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}

} // namespace Galaxy
