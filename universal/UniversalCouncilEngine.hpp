#pragma once
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>

namespace Universal {

struct UniversalDomain {
    std::string domainId;
    std::string name;
    std::vector<std::string> memberRegions;
    float cosmicExtent[3];
    float authorityLevel;
    float unityIndex;
    int64_t formedTimestamp;
};

struct UniversalMandate {
    std::string mandateId;
    std::string name;
    std::string description;
    std::map<std::string, nlohmann::json> provisions;
    float enforcementPriority;
    bool active;
};

struct CosmicCoalition {
    std::string coalitionId;
    std::string name;
    std::vector<std::string> memberDomains;
    std::map<std::string, float> resourcePledges;
    float cohesionIndex;
    int64_t establishedTimestamp;
};

struct OmniversalDirective {
    std::string directiveId;
    std::string name;
    std::string scope; // "universal", "multi_universal", "omniversal"
    nlohmann::json directiveData;
    float adoptionRate;
    int64_t issuedTimestamp;
};

struct UniversalAssembly {
    std::string assemblyId;
    std::string name;
    std::vector<std::string> memberDomains;
    std::map<std::string, float> representationWeights;
    nlohmann::json resolutions;
    std::string assemblyType;
    int64_t lastConvenedTimestamp;
};

class UniversalCouncilEngine {
public:
    static void Init();
    static void Shutdown();
    
    static std::string FormUniversalDomain(const std::string& name,
                                           const std::vector<std::string>& regions,
                                           const float extent[3]);
    static bool DissolveUniversalDomain(const std::string& domainId);
    static UniversalDomain GetUniversalDomain(const std::string& domainId);
    static std::vector<UniversalDomain> GetAllUniversalDomains();
    
    static std::string IssueUniversalMandate(const std::string& name,
                                             const std::string& description,
                                             const std::map<std::string, nlohmann::json>& provisions);
    static bool ActivateMandate(const std::string& mandateId);
    static bool DeactivateMandate(const std::string& mandateId);
    static UniversalMandate GetMandate(const std::string& mandateId);
    static std::vector<UniversalMandate> GetAllMandates();
    
    static std::string FormCosmicCoalition(const std::string& name,
                                           const std::vector<std::string>& domains);
    static bool DissolveCoalition(const std::string& coalitionId);
    static CosmicCoalition GetCoalition(const std::string& coalitionId);
    static std::vector<CosmicCoalition> GetAllCoalitions();
    static float CalculateCoalitionStrength(const std::string& coalitionId);
    
    static std::string IssueOmniversalDirective(const std::string& name,
                                               const std::string& scope,
                                               const nlohmann::json& directiveData);
    static bool RevokeDirective(const std::string& directiveId);
    static OmniversalDirective GetDirective(const std::string& directiveId);
    static std::vector<OmniversalDirective> GetAllDirectives();
    static float CalculateDirectiveAdoption(const std::string& directiveId);
    
    static std::string ConveneUniversalAssembly(const std::string& name,
                                             const std::string& assemblyType,
                                             const std::vector<std::string>& domains);
    static bool ProposeAssemblyResolution(const std::string& assemblyId,
                                          const std::string& resolutionId,
                                          const nlohmann::json& resolution);
    static bool VoteOnAssemblyResolution(const std::string& assemblyId,
                                         const std::string& resolutionId,
                                         const std::string& domainId,
                                         bool approve);
    static UniversalAssembly GetAssembly(const std::string& assemblyId);
    
    static float CalculateUniversalUnity();
    static float CalculateCosmicHarmony();
    static nlohmann::json GetUniversalMetrics();
    static nlohmann::json GenerateUniversalReport();
    
    static void OnTick();
    static bool IsAlive();

private:
    static std::mutex s_mutex;
    static bool s_initialized;
    static std::map<std::string, UniversalDomain> s_domains;
    static std::map<std::string, UniversalMandate> s_mandates;
    static std::map<std::string, CosmicCoalition> s_coalitions;
    static std::map<std::string, OmniversalDirective> s_directives;
    static std::map<std::string, UniversalAssembly> s_assemblies;
    static int64_t s_tickCount;
};

} // namespace Universal
