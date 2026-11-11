#include "infinite/InfiniteHorizonEngine.hpp"
#include <chrono>
#include <algorithm>

namespace Infinite {

std::mutex InfiniteHorizonEngine::s_mutex;
bool InfiniteHorizonEngine::s_initialized = false;
std::map<std::string, UniversalFrontier> InfiniteHorizonEngine::s_frontiers;
std::map<std::string, CosmicBoundary> InfiniteHorizonEngine::s_boundaries;
std::map<std::string, MultiversalThreshold> InfiniteHorizonEngine::s_thresholds;
std::map<std::string, TranscendentLimit> InfiniteHorizonEngine::s_limits;
std::map<std::string, HorizonDiscovery> InfiniteHorizonEngine::s_discoveries;
int64_t InfiniteHorizonEngine::s_tickCount = 0;

void InfiniteHorizonEngine::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (s_initialized) return;
    s_initialized = true;
    s_tickCount = 0;
}

void InfiniteHorizonEngine::Shutdown() {
    std::lock_guard<std::mutex> lock(s_mutex);
    s_initialized = false;
    s_frontiers.clear();
    s_boundaries.clear();
    s_thresholds.clear();
    s_limits.clear();
    s_discoveries.clear();
}

std::string InfiniteHorizonEngine::EstablishUniversalFrontier(const std::string& name,
                                                              const std::string& frontierType,
                                                              const std::string& parentUniverse) {
    std::lock_guard<std::mutex> lock(s_mutex);
    static int frontierCounter = 0;
    std::string frontierId = "universal_frontier_" + std::to_string(++frontierCounter);
    
    UniversalFrontier frontier;
    frontier.frontierId = frontierId;
    frontier.name = name;
    frontier.frontierType = frontierType;
    frontier.parentUniverse = parentUniverse;
    frontier.expansionRate = 1.0f;
    frontier.stabilityIndex = 1.0f;
    frontier.establishedTimestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_frontiers[frontierId] = frontier;
    return frontierId;
}

bool InfiniteHorizonEngine::ExpandFrontier(const std::string& frontierId, const std::string& regionId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_frontiers.find(frontierId);
    if (it == s_frontiers.end()) return false;
    it->second.discoveredRegions.push_back(regionId);
    return true;
}

bool InfiniteHorizonEngine::StabilizeFrontier(const std::string& frontierId, float stabilityBoost) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_frontiers.find(frontierId);
    if (it == s_frontiers.end()) return false;
    it->second.stabilityIndex = std::min(1.0f, it->second.stabilityIndex + stabilityBoost);
    return true;
}

bool InfiniteHorizonEngine::SetExpansionRate(const std::string& frontierId, float rate) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_frontiers.find(frontierId);
    if (it == s_frontiers.end()) return false;
    it->second.expansionRate = std::max(0.0f, rate);
    return true;
}

UniversalFrontier InfiniteHorizonEngine::GetFrontier(const std::string& frontierId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_frontiers.find(frontierId);
    if (it != s_frontiers.end()) return it->second;
    return UniversalFrontier{};
}

std::vector<UniversalFrontier> InfiniteHorizonEngine::GetAllFrontiers() {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<UniversalFrontier> result;
    for (const auto& [id, frontier] : s_frontiers) {
        result.push_back(frontier);
    }
    return result;
}

std::vector<UniversalFrontier> InfiniteHorizonEngine::GetFrontiersByType(const std::string& frontierType) {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<UniversalFrontier> result;
    for (const auto& [id, frontier] : s_frontiers) {
        if (frontier.frontierType == frontierType) result.push_back(frontier);
    }
    return result;
}

std::string InfiniteHorizonEngine::DetectCosmicBoundary(const std::string& name,
                                                        const std::string& boundaryType,
                                                        float strength) {
    std::lock_guard<std::mutex> lock(s_mutex);
    static int boundaryCounter = 0;
    std::string boundaryId = "cosmic_boundary_" + std::to_string(++boundaryCounter);
    
    CosmicBoundary boundary;
    boundary.boundaryId = boundaryId;
    boundary.name = name;
    boundary.boundaryType = boundaryType;
    boundary.boundaryStrength = strength;
    boundary.permeability = 0.5f;
    boundary.detectedTimestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_boundaries[boundaryId] = boundary;
    return boundaryId;
}

bool InfiniteHorizonEngine::ReinforceBoundary(const std::string& boundaryId, float strengthBoost) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_boundaries.find(boundaryId);
    if (it == s_boundaries.end()) return false;
    it->second.boundaryStrength = std::min(1.0f, it->second.boundaryStrength + strengthBoost);
    return true;
}

bool InfiniteHorizonEngine::AdjustPermeability(const std::string& boundaryId, float permeability) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_boundaries.find(boundaryId);
    if (it == s_boundaries.end()) return false;
    it->second.permeability = std::min(1.0f, std::max(0.0f, permeability));
    return true;
}

bool InfiniteHorizonEngine::RegisterCrossingPoint(const std::string& boundaryId, const std::string& pointId, float accessibility) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_boundaries.find(boundaryId);
    if (it == s_boundaries.end()) return false;
    it->second.crossingPoints[pointId] = accessibility;
    return true;
}

CosmicBoundary InfiniteHorizonEngine::GetBoundary(const std::string& boundaryId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_boundaries.find(boundaryId);
    if (it != s_boundaries.end()) return it->second;
    return CosmicBoundary{};
}

std::vector<CosmicBoundary> InfiniteHorizonEngine::GetAllBoundaries() {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<CosmicBoundary> result;
    for (const auto& [id, boundary] : s_boundaries) {
        result.push_back(boundary);
    }
    return result;
}

std::vector<CosmicBoundary> InfiniteHorizonEngine::GetBoundariesByType(const std::string& boundaryType) {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<CosmicBoundary> result;
    for (const auto& [id, boundary] : s_boundaries) {
        if (boundary.boundaryType == boundaryType) result.push_back(boundary);
    }
    return result;
}

std::string InfiniteHorizonEngine::IdentifyMultiversalThreshold(const std::string& name,
                                                                const std::string& thresholdClass,
                                                                const std::vector<std::string>& universes) {
    std::lock_guard<std::mutex> lock(s_mutex);
    static int thresholdCounter = 0;
    std::string thresholdId = "multiversal_threshold_" + std::to_string(++thresholdCounter);
    
    MultiversalThreshold threshold;
    threshold.thresholdId = thresholdId;
    threshold.name = name;
    threshold.thresholdClass = thresholdClass;
    threshold.connectedUniverses = universes;
    threshold.transitionEnergy = 1000.0f;
    threshold.stabilityFactor = 1.0f;
    threshold.identifiedTimestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_thresholds[thresholdId] = threshold;
    return thresholdId;
}

bool InfiniteHorizonEngine::StabilizeThreshold(const std::string& thresholdId, float stabilityBoost) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_thresholds.find(thresholdId);
    if (it == s_thresholds.end()) return false;
    it->second.stabilityFactor = std::min(1.0f, it->second.stabilityFactor + stabilityBoost);
    return true;
}

bool InfiniteHorizonEngine::AdjustTransitionEnergy(const std::string& thresholdId, float energy) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_thresholds.find(thresholdId);
    if (it == s_thresholds.end()) return false;
    it->second.transitionEnergy = std::max(0.0f, energy);
    return true;
}

MultiversalThreshold InfiniteHorizonEngine::GetThreshold(const std::string& thresholdId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_thresholds.find(thresholdId);
    if (it != s_thresholds.end()) return it->second;
    return MultiversalThreshold{};
}

std::vector<MultiversalThreshold> InfiniteHorizonEngine::GetAllThresholds() {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<MultiversalThreshold> result;
    for (const auto& [id, threshold] : s_thresholds) {
        result.push_back(threshold);
    }
    return result;
}

std::vector<MultiversalThreshold> InfiniteHorizonEngine::GetThresholdsByClass(const std::string& thresholdClass) {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<MultiversalThreshold> result;
    for (const auto& [id, threshold] : s_thresholds) {
        if (threshold.thresholdClass == thresholdClass) result.push_back(threshold);
    }
    return result;
}

std::string InfiniteHorizonEngine::DiscoverTranscendentLimit(const std::string& name,
                                                             const std::string& limitCategory,
                                                             float maximumValue) {
    std::lock_guard<std::mutex> lock(s_mutex);
    static int limitCounter = 0;
    std::string limitId = "transcendent_limit_" + std::to_string(++limitCounter);
    
    TranscendentLimit limit;
    limit.limitId = limitId;
    limit.name = name;
    limit.limitCategory = limitCategory;
    limit.currentValue = 0.0f;
    limit.maximumValue = maximumValue;
    limit.expansionProgress = 0.0f;
    limit.discoveredTimestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_limits[limitId] = limit;
    return limitId;
}

bool InfiniteHorizonEngine::ExpandLimit(const std::string& limitId, float expansion) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_limits.find(limitId);
    if (it == s_limits.end()) return false;
    it->second.currentValue = std::min(it->second.maximumValue, it->second.currentValue + expansion);
    it->second.expansionProgress = it->second.currentValue / it->second.maximumValue;
    return true;
}

bool InfiniteHorizonEngine::PushLimitBoundary(const std::string& limitId, float newMaximum) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_limits.find(limitId);
    if (it == s_limits.end()) return false;
    it->second.maximumValue = newMaximum;
    it->second.expansionProgress = it->second.currentValue / it->second.maximumValue;
    return true;
}

TranscendentLimit InfiniteHorizonEngine::GetLimit(const std::string& limitId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_limits.find(limitId);
    if (it != s_limits.end()) return it->second;
    return TranscendentLimit{};
}

std::vector<TranscendentLimit> InfiniteHorizonEngine::GetAllLimits() {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<TranscendentLimit> result;
    for (const auto& [id, limit] : s_limits) {
        result.push_back(limit);
    }
    return result;
}

std::vector<TranscendentLimit> InfiniteHorizonEngine::GetLimitsByCategory(const std::string& limitCategory) {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<TranscendentLimit> result;
    for (const auto& [id, limit] : s_limits) {
        if (limit.limitCategory == limitCategory) result.push_back(limit);
    }
    return result;
}

std::string InfiniteHorizonEngine::RecordHorizonDiscovery(const std::string& name,
                                                          const std::string& discoveryType,
                                                          const std::string& frontierId,
                                                          const nlohmann::json& data,
                                                          float significance) {
    std::lock_guard<std::mutex> lock(s_mutex);
    static int discoveryCounter = 0;
    std::string discoveryId = "horizon_discovery_" + std::to_string(++discoveryCounter);
    
    HorizonDiscovery discovery;
    discovery.discoveryId = discoveryId;
    discovery.name = name;
    discovery.discoveryType = discoveryType;
    discovery.frontierId = frontierId;
    discovery.discoveryData = data;
    discovery.significance = significance;
    discovery.discoveredTimestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_discoveries[discoveryId] = discovery;
    return discoveryId;
}

HorizonDiscovery InfiniteHorizonEngine::GetDiscovery(const std::string& discoveryId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_discoveries.find(discoveryId);
    if (it != s_discoveries.end()) return it->second;
    return HorizonDiscovery{};
}

std::vector<HorizonDiscovery> InfiniteHorizonEngine::GetAllDiscoveries() {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<HorizonDiscovery> result;
    for (const auto& [id, discovery] : s_discoveries) {
        result.push_back(discovery);
    }
    return result;
}

std::vector<HorizonDiscovery> InfiniteHorizonEngine::GetDiscoveriesByFrontier(const std::string& frontierId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<HorizonDiscovery> result;
    for (const auto& [id, discovery] : s_discoveries) {
        if (discovery.frontierId == frontierId) result.push_back(discovery);
    }
    return result;
}

float InfiniteHorizonEngine::CalculateTotalExpansion() {
    std::lock_guard<std::mutex> lock(s_mutex);
    float totalExpansion = 0.0f;
    for (const auto& [id, frontier] : s_frontiers) {
        totalExpansion += frontier.expansionRate * frontier.discoveredRegions.size();
    }
    return totalExpansion;
}

float InfiniteHorizonEngine::CalculateBoundaryIntegrity() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (s_boundaries.empty()) return 1.0f;
    float totalIntegrity = 0.0f;
    for (const auto& [id, boundary] : s_boundaries) {
        totalIntegrity += boundary.boundaryStrength;
    }
    return totalIntegrity / s_boundaries.size();
}

nlohmann::json InfiniteHorizonEngine::GetHorizonMetrics() {
    std::lock_guard<std::mutex> lock(s_mutex);
    nlohmann::json metrics;
    metrics["frontierCount"] = s_frontiers.size();
    metrics["boundaryCount"] = s_boundaries.size();
    metrics["thresholdCount"] = s_thresholds.size();
    metrics["limitCount"] = s_limits.size();
    metrics["discoveryCount"] = s_discoveries.size();
    metrics["totalExpansion"] = CalculateTotalExpansion();
    metrics["boundaryIntegrity"] = CalculateBoundaryIntegrity();
    metrics["tickCount"] = s_tickCount;
    return metrics;
}

nlohmann::json InfiniteHorizonEngine::GenerateHorizonReport() {
    nlohmann::json report;
    report["metrics"] = GetHorizonMetrics();
    report["activeFrontiers"] = nlohmann::json::array();
    report["majorBoundaries"] = nlohmann::json::array();
    report["significantDiscoveries"] = nlohmann::json::array();
    
    for (const auto& frontier : GetAllFrontiers()) {
        nlohmann::json f;
        f["id"] = frontier.frontierId;
        f["name"] = frontier.name;
        f["type"] = frontier.frontierType;
        f["expansionRate"] = frontier.expansionRate;
        f["regionsDiscovered"] = frontier.discoveredRegions.size();
        report["activeFrontiers"].push_back(f);
    }
    
    for (const auto& boundary : GetAllBoundaries()) {
        nlohmann::json b;
        b["id"] = boundary.boundaryId;
        b["name"] = boundary.name;
        b["type"] = boundary.boundaryType;
        b["strength"] = boundary.boundaryStrength;
        b["permeability"] = boundary.permeability;
        report["majorBoundaries"].push_back(b);
    }
    
    return report;
}

void InfiniteHorizonEngine::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    s_tickCount++;
    
    for (auto& [id, frontier] : s_frontiers) {
        frontier.stabilityIndex *= 0.9999f;
        frontier.stabilityIndex += 0.0001f;
    }
    
    for (auto& [id, boundary] : s_boundaries) {
        boundary.boundaryStrength *= 0.9999f;
        boundary.boundaryStrength += 0.0001f;
    }
    
    for (auto& [id, threshold] : s_thresholds) {
        threshold.stabilityFactor *= 0.9999f;
        threshold.stabilityFactor += 0.0001f;
    }
}

bool InfiniteHorizonEngine::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}

} // namespace Infinite
