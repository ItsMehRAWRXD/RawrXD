#pragma once
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>

namespace Supercluster {

struct SuperclusterRegion {
    std::string regionId;
    std::string name;
    std::vector<std::string> memberSuperclusters;
    float cosmicPosition[3];
    float influenceRadius;
    float governanceStrength;
    float coherence;
    int64_t formedTimestamp;
};

struct GovernanceProtocol {
    std::string protocolId;
    std::string name;
    std::string description;
    std::map<std::string, nlohmann::json> rules;
    float enforcementLevel;
    bool active;
};

struct InterSuperclusterAlliance {
    std::string allianceId;
    std::string name;
    std::vector<std::string> memberRegions;
    std::map<std::string, float> resourceCommitments;
    float solidarityIndex;
    int64_t establishedTimestamp;
};

struct CosmicPolicy {
    std::string policyId;
    std::string name;
    std::string scope; // "regional", "inter_regional", "universal"
    nlohmann::json policyData;
    float complianceRate;
    int64_t enactedTimestamp;
};

struct SuperclusterCouncil {
    std::string councilId;
    std::string name;
    std::vector<std::string> memberRegions;
    std::map<std::string, float> votingPower;
    nlohmann::json resolutions;
    std::string councilType; // "economic", "military", "cultural", "scientific"
    int64_t lastSessionTimestamp;
};

class SuperclusterGovernanceEngine {
public:
    static void Init();
    static void Shutdown();
    
    static std::string FormSuperclusterRegion(const std::string& name,
                                               const std::vector<std::string>& superclusters,
                                               const float position[3]);
    static bool DissolveSuperclusterRegion(const std::string& regionId);
    static SuperclusterRegion GetSuperclusterRegion(const std::string& regionId);
    static std::vector<SuperclusterRegion> GetAllSuperclusterRegions();
    
    static std::string DefineGovernanceProtocol(const std::string& name,
                                               const std::string& description,
                                               const std::map<std::string, nlohmann::json>& rules);
    static bool ActivateProtocol(const std::string& protocolId);
    static bool DeactivateProtocol(const std::string& protocolId);
    static GovernanceProtocol GetProtocol(const std::string& protocolId);
    static std::vector<GovernanceProtocol> GetAllProtocols();
    
    static std::string FormInterSuperclusterAlliance(const std::string& name,
                                                     const std::vector<std::string>& regions);
    static bool DissolveAlliance(const std::string& allianceId);
    static InterSuperclusterAlliance GetAlliance(const std::string& allianceId);
    static std::vector<InterSuperclusterAlliance> GetAllAlliances();
    static float CalculateAllianceStrength(const std::string& allianceId);
    
    static std::string EnactCosmicPolicy(const std::string& name,
                                        const std::string& scope,
                                        const nlohmann::json& policyData);
    static bool RevokePolicy(const std::string& policyId);
    static CosmicPolicy GetPolicy(const std::string& policyId);
    static std::vector<CosmicPolicy> GetAllPolicies();
    static float CalculatePolicyCompliance(const std::string& policyId);
    
    static std::string ConveneSuperclusterCouncil(const std::string& name,
                                                 const std::string& councilType,
                                                 const std::vector<std::string>& regions);
    static bool ProposeResolution(const std::string& councilId,
                                  const std::string& resolutionId,
                                  const nlohmann::json& resolution);
    static bool VoteOnResolution(const std::string& councilId,
                                 const std::string& resolutionId,
                                 const std::string& regionId,
                                 bool approve);
    static SuperclusterCouncil GetCouncil(const std::string& councilId);
    
    static float CalculateGovernanceCoherence();
    static float CalculateInterRegionalStability();
    static nlohmann::json GetGovernanceMetrics();
    static nlohmann::json GenerateGovernanceReport();
    
    static void OnTick();
    static bool IsAlive();

private:
    static std::mutex s_mutex;
    static bool s_initialized;
    static std::map<std::string, SuperclusterRegion> s_regions;
    static std::map<std::string, GovernanceProtocol> s_protocols;
    static std::map<std::string, InterSuperclusterAlliance> s_alliances;
    static std::map<std::string, CosmicPolicy> s_policies;
    static std::map<std::string, SuperclusterCouncil> s_councils;
    static int64_t s_tickCount;
};

} // namespace Supercluster
