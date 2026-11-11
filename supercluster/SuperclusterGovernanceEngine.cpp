#include "supercluster/SuperclusterGovernanceEngine.hpp"
#include <chrono>
#include <algorithm>

namespace Supercluster {

std::mutex SuperclusterGovernanceEngine::s_mutex;
bool SuperclusterGovernanceEngine::s_initialized = false;
std::map<std::string, SuperclusterRegion> SuperclusterGovernanceEngine::s_regions;
std::map<std::string, GovernanceProtocol> SuperclusterGovernanceEngine::s_protocols;
std::map<std::string, InterSuperclusterAlliance> SuperclusterGovernanceEngine::s_alliances;
std::map<std::string, CosmicPolicy> SuperclusterGovernanceEngine::s_policies;
std::map<std::string, SuperclusterCouncil> SuperclusterGovernanceEngine::s_councils;
int64_t SuperclusterGovernanceEngine::s_tickCount = 0;

void SuperclusterGovernanceEngine::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (s_initialized) return;
    
    s_initialized = true;
    s_tickCount = 0;
}

void SuperclusterGovernanceEngine::Shutdown() {
    std::lock_guard<std::mutex> lock(s_mutex);
    s_initialized = false;
    s_regions.clear();
    s_protocols.clear();
    s_alliances.clear();
    s_policies.clear();
    s_councils.clear();
}

std::string SuperclusterGovernanceEngine::FormSuperclusterRegion(const std::string& name,
                                                                const std::vector<std::string>& superclusters,
                                                                const float position[3]) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    static int regionCounter = 0;
    std::string regionId = "supercluster_region_" + std::to_string(++regionCounter);
    
    SuperclusterRegion region;
    region.regionId = regionId;
    region.name = name;
    region.memberSuperclusters = superclusters;
    region.cosmicPosition[0] = position[0];
    region.cosmicPosition[1] = position[1];
    region.cosmicPosition[2] = position[2];
    region.influenceRadius = static_cast<float>(superclusters.size()) * 50.0f;
    region.governanceStrength = 1.0f;
    region.coherence = 1.0f;
    region.formedTimestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_regions[regionId] = region;
    return regionId;
}

bool SuperclusterGovernanceEngine::DissolveSuperclusterRegion(const std::string& regionId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    auto it = s_regions.find(regionId);
    if (it == s_regions.end()) return false;
    
    s_regions.erase(it);
    return true;
}

SuperclusterRegion SuperclusterGovernanceEngine::GetSuperclusterRegion(const std::string& regionId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    auto it = s_regions.find(regionId);
    if (it != s_regions.end()) return it->second;
    return SuperclusterRegion{};
}

std::vector<SuperclusterRegion> SuperclusterGovernanceEngine::GetAllSuperclusterRegions() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    std::vector<SuperclusterRegion> result;
    for (const auto& [id, region] : s_regions) {
        result.push_back(region);
    }
    return result;
}

std::string SuperclusterGovernanceEngine::DefineGovernanceProtocol(const std::string& name,
                                                                   const std::string& description,
                                                                   const std::map<std::string, nlohmann::json>& rules) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    static int protocolCounter = 0;
    std::string protocolId = "protocol_" + std::to_string(++protocolCounter);
    
    GovernanceProtocol protocol;
    protocol.protocolId = protocolId;
    protocol.name = name;
    protocol.description = description;
    protocol.rules = rules;
    protocol.enforcementLevel = 1.0f;
    protocol.active = true;
    
    s_protocols[protocolId] = protocol;
    return protocolId;
}

bool SuperclusterGovernanceEngine::ActivateProtocol(const std::string& protocolId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    auto it = s_protocols.find(protocolId);
    if (it == s_protocols.end()) return false;
    
    it->second.active = true;
    return true;
}

bool SuperclusterGovernanceEngine::DeactivateProtocol(const std::string& protocolId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    auto it = s_protocols.find(protocolId);
    if (it == s_protocols.end()) return false;
    
    it->second.active = false;
    return true;
}

GovernanceProtocol SuperclusterGovernanceEngine::GetProtocol(const std::string& protocolId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    auto it = s_protocols.find(protocolId);
    if (it != s_protocols.end()) return it->second;
    return GovernanceProtocol{};
}

std::vector<GovernanceProtocol> SuperclusterGovernanceEngine::GetAllProtocols() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    std::vector<GovernanceProtocol> result;
    for (const auto& [id, protocol] : s_protocols) {
        result.push_back(protocol);
    }
    return result;
}

std::string SuperclusterGovernanceEngine::FormInterSuperclusterAlliance(const std::string& name,
                                                                         const std::vector<std::string>& regions) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    static int allianceCounter = 0;
    std::string allianceId = "alliance_" + std::to_string(++allianceCounter);
    
    InterSuperclusterAlliance alliance;
    alliance.allianceId = allianceId;
    alliance.name = name;
    alliance.memberRegions = regions;
    alliance.solidarityIndex = 1.0f;
    alliance.establishedTimestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_alliances[allianceId] = alliance;
    return allianceId;
}

bool SuperclusterGovernanceEngine::DissolveAlliance(const std::string& allianceId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    auto it = s_alliances.find(allianceId);
    if (it == s_alliances.end()) return false;
    
    s_alliances.erase(it);
    return true;
}

InterSuperclusterAlliance SuperclusterGovernanceEngine::GetAlliance(const std::string& allianceId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    auto it = s_alliances.find(allianceId);
    if (it != s_alliances.end()) return it->second;
    return InterSuperclusterAlliance{};
}

std::vector<InterSuperclusterAlliance> SuperclusterGovernanceEngine::GetAllAlliances() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    std::vector<InterSuperclusterAlliance> result;
    for (const auto& [id, alliance] : s_alliances) {
        result.push_back(alliance);
    }
    return result;
}

float SuperclusterGovernanceEngine::CalculateAllianceStrength(const std::string& allianceId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    auto it = s_alliances.find(allianceId);
    if (it == s_alliances.end()) return 0.0f;
    
    return it->second.solidarityIndex * static_cast<float>(it->second.memberRegions.size());
}

std::string SuperclusterGovernanceEngine::EnactCosmicPolicy(const std::string& name,
                                                           const std::string& scope,
                                                           const nlohmann::json& policyData) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    static int policyCounter = 0;
    std::string policyId = "policy_" + std::to_string(++policyCounter);
    
    CosmicPolicy policy;
    policy.policyId = policyId;
    policy.name = name;
    policy.scope = scope;
    policy.policyData = policyData;
    policy.complianceRate = 1.0f;
    policy.enactedTimestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_policies[policyId] = policy;
    return policyId;
}

bool SuperclusterGovernanceEngine::RevokePolicy(const std::string& policyId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    auto it = s_policies.find(policyId);
    if (it == s_policies.end()) return false;
    
    s_policies.erase(it);
    return true;
}

CosmicPolicy SuperclusterGovernanceEngine::GetPolicy(const std::string& policyId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    auto it = s_policies.find(policyId);
    if (it != s_policies.end()) return it->second;
    return CosmicPolicy{};
}

std::vector<CosmicPolicy> SuperclusterGovernanceEngine::GetAllPolicies() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    std::vector<CosmicPolicy> result;
    for (const auto& [id, policy] : s_policies) {
        result.push_back(policy);
    }
    return result;
}

float SuperclusterGovernanceEngine::CalculatePolicyCompliance(const std::string& policyId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    auto it = s_policies.find(policyId);
    if (it == s_policies.end()) return 0.0f;
    
    return it->second.complianceRate;
}

std::string SuperclusterGovernanceEngine::ConveneSuperclusterCouncil(const std::string& name,
                                                                     const std::string& councilType,
                                                                     const std::vector<std::string>& regions) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    static int councilCounter = 0;
    std::string councilId = "supercluster_council_" + std::to_string(++councilCounter);
    
    SuperclusterCouncil council;
    council.councilId = councilId;
    council.name = name;
    council.councilType = councilType;
    council.memberRegions = regions;
    
    float equalPower = 1.0f / regions.size();
    for (const auto& region : regions) {
        council.votingPower[region] = equalPower;
    }
    
    council.lastSessionTimestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_councils[councilId] = council;
    return councilId;
}

bool SuperclusterGovernanceEngine::ProposeResolution(const std::string& councilId,
                                                     const std::string& resolutionId,
                                                     const nlohmann::json& resolution) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    auto it = s_councils.find(councilId);
    if (it == s_councils.end()) return false;
    
    it->second.resolutions[resolutionId] = resolution;
    return true;
}

bool SuperclusterGovernanceEngine::VoteOnResolution(const std::string& councilId,
                                                    const std::string& resolutionId,
                                                    const std::string& regionId,
                                                    bool approve) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    auto it = s_councils.find(councilId);
    if (it == s_councils.end()) return false;
    
    auto resIt = it->second.resolutions.find(resolutionId);
    if (resIt == it->second.resolutions.end()) return false;
    
    resIt->second["votes"][regionId] = approve;
    return true;
}

SuperclusterCouncil SuperclusterGovernanceEngine::GetCouncil(const std::string& councilId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    auto it = s_councils.find(councilId);
    if (it != s_councils.end()) return it->second;
    return SuperclusterCouncil{};
}

float SuperclusterGovernanceEngine::CalculateGovernanceCoherence() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    if (s_regions.empty()) return 1.0f;
    
    float totalCoherence = 0.0f;
    for (const auto& [id, region] : s_regions) {
        totalCoherence += region.coherence;
    }
    return totalCoherence / s_regions.size();
}

float SuperclusterGovernanceEngine::CalculateInterRegionalStability() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    if (s_alliances.empty()) return 1.0f;
    
    float totalStability = 0.0f;
    for (const auto& [id, alliance] : s_alliances) {
        totalStability += alliance.solidarityIndex;
    }
    return totalStability / s_alliances.size();
}

nlohmann::json SuperclusterGovernanceEngine::GetGovernanceMetrics() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    nlohmann::json metrics;
    metrics["regionCount"] = s_regions.size();
    metrics["protocolCount"] = s_protocols.size();
    metrics["allianceCount"] = s_alliances.size();
    metrics["policyCount"] = s_policies.size();
    metrics["councilCount"] = s_councils.size();
    metrics["governanceCoherence"] = CalculateGovernanceCoherence();
    metrics["interRegionalStability"] = CalculateInterRegionalStability();
    metrics["tickCount"] = s_tickCount;
    return metrics;
}

nlohmann::json SuperclusterGovernanceEngine::GenerateGovernanceReport() {
    nlohmann::json report;
    report["metrics"] = GetGovernanceMetrics();
    report["regions"] = nlohmann::json::array();
    report["protocols"] = nlohmann::json::array();
    report["alliances"] = nlohmann::json::array();
    
    for (const auto& region : GetAllSuperclusterRegions()) {
        nlohmann::json r;
        r["id"] = region.regionId;
        r["name"] = region.name;
        r["superclusterCount"] = region.memberSuperclusters.size();
        r["coherence"] = region.coherence;
        r["governanceStrength"] = region.governanceStrength;
        report["regions"].push_back(r);
    }
    
    for (const auto& protocol : GetAllProtocols()) {
        nlohmann::json p;
        p["id"] = protocol.protocolId;
        p["name"] = protocol.name;
        p["active"] = protocol.active;
        p["enforcementLevel"] = protocol.enforcementLevel;
        report["protocols"].push_back(p);
    }
    
    return report;
}

void SuperclusterGovernanceEngine::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    s_tickCount++;
    
    for (auto& [id, region] : s_regions) {
        region.coherence *= 0.9999f;
        region.coherence += 0.0001f;
        region.governanceStrength *= 0.9999f;
        region.governanceStrength += 0.0001f;
    }
    
    for (auto& [id, alliance] : s_alliances) {
        alliance.solidarityIndex *= 0.9999f;
        alliance.solidarityIndex += 0.0001f;
    }
}

bool SuperclusterGovernanceEngine::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}

} // namespace Supercluster
