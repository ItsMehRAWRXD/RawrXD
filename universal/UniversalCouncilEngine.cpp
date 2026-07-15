#include "universal/UniversalCouncilEngine.hpp"
#include <chrono>
#include <algorithm>

namespace Universal {

std::mutex UniversalCouncilEngine::s_mutex;
bool UniversalCouncilEngine::s_initialized = false;
std::map<std::string, UniversalDomain> UniversalCouncilEngine::s_domains;
std::map<std::string, UniversalMandate> UniversalCouncilEngine::s_mandates;
std::map<std::string, CosmicCoalition> UniversalCouncilEngine::s_coalitions;
std::map<std::string, OmniversalDirective> UniversalCouncilEngine::s_directives;
std::map<std::string, UniversalAssembly> UniversalCouncilEngine::s_assemblies;
int64_t UniversalCouncilEngine::s_tickCount = 0;

void UniversalCouncilEngine::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (s_initialized) return;
    s_initialized = true;
    s_tickCount = 0;
}

void UniversalCouncilEngine::Shutdown() {
    std::lock_guard<std::mutex> lock(s_mutex);
    s_initialized = false;
    s_domains.clear();
    s_mandates.clear();
    s_coalitions.clear();
    s_directives.clear();
    s_assemblies.clear();
}

std::string UniversalCouncilEngine::FormUniversalDomain(const std::string& name,
                                                       const std::vector<std::string>& regions,
                                                       const float extent[3]) {
    std::lock_guard<std::mutex> lock(s_mutex);
    static int domainCounter = 0;
    std::string domainId = "universal_domain_" + std::to_string(++domainCounter);
    
    UniversalDomain domain;
    domain.domainId = domainId;
    domain.name = name;
    domain.memberRegions = regions;
    domain.cosmicExtent[0] = extent[0];
    domain.cosmicExtent[1] = extent[1];
    domain.cosmicExtent[2] = extent[2];
    domain.authorityLevel = 1.0f;
    domain.unityIndex = 1.0f;
    domain.formedTimestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_domains[domainId] = domain;
    return domainId;
}

bool UniversalCouncilEngine::DissolveUniversalDomain(const std::string& domainId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_domains.find(domainId);
    if (it == s_domains.end()) return false;
    s_domains.erase(it);
    return true;
}

UniversalDomain UniversalCouncilEngine::GetUniversalDomain(const std::string& domainId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_domains.find(domainId);
    if (it != s_domains.end()) return it->second;
    return UniversalDomain{};
}

std::vector<UniversalDomain> UniversalCouncilEngine::GetAllUniversalDomains() {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<UniversalDomain> result;
    for (const auto& [id, domain] : s_domains) {
        result.push_back(domain);
    }
    return result;
}

std::string UniversalCouncilEngine::IssueUniversalMandate(const std::string& name,
                                                         const std::string& description,
                                                         const std::map<std::string, nlohmann::json>& provisions) {
    std::lock_guard<std::mutex> lock(s_mutex);
    static int mandateCounter = 0;
    std::string mandateId = "mandate_" + std::to_string(++mandateCounter);
    
    UniversalMandate mandate;
    mandate.mandateId = mandateId;
    mandate.name = name;
    mandate.description = description;
    mandate.provisions = provisions;
    mandate.enforcementPriority = 1.0f;
    mandate.active = true;
    
    s_mandates[mandateId] = mandate;
    return mandateId;
}

bool UniversalCouncilEngine::ActivateMandate(const std::string& mandateId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_mandates.find(mandateId);
    if (it == s_mandates.end()) return false;
    it->second.active = true;
    return true;
}

bool UniversalCouncilEngine::DeactivateMandate(const std::string& mandateId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_mandates.find(mandateId);
    if (it == s_mandates.end()) return false;
    it->second.active = false;
    return true;
}

UniversalMandate UniversalCouncilEngine::GetMandate(const std::string& mandateId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_mandates.find(mandateId);
    if (it != s_mandates.end()) return it->second;
    return UniversalMandate{};
}

std::vector<UniversalMandate> UniversalCouncilEngine::GetAllMandates() {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<UniversalMandate> result;
    for (const auto& [id, mandate] : s_mandates) {
        result.push_back(mandate);
    }
    return result;
}

std::string UniversalCouncilEngine::FormCosmicCoalition(const std::string& name,
                                                         const std::vector<std::string>& domains) {
    std::lock_guard<std::mutex> lock(s_mutex);
    static int coalitionCounter = 0;
    std::string coalitionId = "coalition_" + std::to_string(++coalitionCounter);
    
    CosmicCoalition coalition;
    coalition.coalitionId = coalitionId;
    coalition.name = name;
    coalition.memberDomains = domains;
    coalition.cohesionIndex = 1.0f;
    coalition.establishedTimestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_coalitions[coalitionId] = coalition;
    return coalitionId;
}

bool UniversalCouncilEngine::DissolveCoalition(const std::string& coalitionId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_coalitions.find(coalitionId);
    if (it == s_coalitions.end()) return false;
    s_coalitions.erase(it);
    return true;
}

CosmicCoalition UniversalCouncilEngine::GetCoalition(const std::string& coalitionId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_coalitions.find(coalitionId);
    if (it != s_coalitions.end()) return it->second;
    return CosmicCoalition{};
}

std::vector<CosmicCoalition> UniversalCouncilEngine::GetAllCoalitions() {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<CosmicCoalition> result;
    for (const auto& [id, coalition] : s_coalitions) {
        result.push_back(coalition);
    }
    return result;
}

float UniversalCouncilEngine::CalculateCoalitionStrength(const std::string& coalitionId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_coalitions.find(coalitionId);
    if (it == s_coalitions.end()) return 0.0f;
    return it->second.cohesionIndex * static_cast<float>(it->second.memberDomains.size());
}

std::string UniversalCouncilEngine::IssueOmniversalDirective(const std::string& name,
                                                            const std::string& scope,
                                                            const nlohmann::json& directiveData) {
    std::lock_guard<std::mutex> lock(s_mutex);
    static int directiveCounter = 0;
    std::string directiveId = "directive_" + std::to_string(++directiveCounter);
    
    OmniversalDirective directive;
    directive.directiveId = directiveId;
    directive.name = name;
    directive.scope = scope;
    directive.directiveData = directiveData;
    directive.adoptionRate = 1.0f;
    directive.issuedTimestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_directives[directiveId] = directive;
    return directiveId;
}

bool UniversalCouncilEngine::RevokeDirective(const std::string& directiveId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_directives.find(directiveId);
    if (it == s_directives.end()) return false;
    s_directives.erase(it);
    return true;
}

OmniversalDirective UniversalCouncilEngine::GetDirective(const std::string& directiveId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_directives.find(directiveId);
    if (it != s_directives.end()) return it->second;
    return OmniversalDirective{};
}

std::vector<OmniversalDirective> UniversalCouncilEngine::GetAllDirectives() {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<OmniversalDirective> result;
    for (const auto& [id, directive] : s_directives) {
        result.push_back(directive);
    }
    return result;
}

float UniversalCouncilEngine::CalculateDirectiveAdoption(const std::string& directiveId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_directives.find(directiveId);
    if (it == s_directives.end()) return 0.0f;
    return it->second.adoptionRate;
}

std::string UniversalCouncilEngine::ConveneUniversalAssembly(const std::string& name,
                                                             const std::string& assemblyType,
                                                             const std::vector<std::string>& domains) {
    std::lock_guard<std::mutex> lock(s_mutex);
    static int assemblyCounter = 0;
    std::string assemblyId = "universal_assembly_" + std::to_string(++assemblyCounter);
    
    UniversalAssembly assembly;
    assembly.assemblyId = assemblyId;
    assembly.name = name;
    assembly.assemblyType = assemblyType;
    assembly.memberDomains = domains;
    
    float equalWeight = 1.0f / domains.size();
    for (const auto& domain : domains) {
        assembly.representationWeights[domain] = equalWeight;
    }
    
    assembly.lastConvenedTimestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_assemblies[assemblyId] = assembly;
    return assemblyId;
}

bool UniversalCouncilEngine::ProposeAssemblyResolution(const std::string& assemblyId,
                                                     const std::string& resolutionId,
                                                     const nlohmann::json& resolution) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_assemblies.find(assemblyId);
    if (it == s_assemblies.end()) return false;
    it->second.resolutions[resolutionId] = resolution;
    return true;
}

bool UniversalCouncilEngine::VoteOnAssemblyResolution(const std::string& assemblyId,
                                                       const std::string& resolutionId,
                                                       const std::string& domainId,
                                                       bool approve) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_assemblies.find(assemblyId);
    if (it == s_assemblies.end()) return false;
    auto resIt = it->second.resolutions.find(resolutionId);
    if (resIt == it->second.resolutions.end()) return false;
    resIt->second["votes"][domainId] = approve;
    return true;
}

UniversalAssembly UniversalCouncilEngine::GetAssembly(const std::string& assemblyId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_assemblies.find(assemblyId);
    if (it != s_assemblies.end()) return it->second;
    return UniversalAssembly{};
}

float UniversalCouncilEngine::CalculateUniversalUnity() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (s_domains.empty()) return 1.0f;
    float totalUnity = 0.0f;
    for (const auto& [id, domain] : s_domains) {
        totalUnity += domain.unityIndex;
    }
    return totalUnity / s_domains.size();
}

float UniversalCouncilEngine::CalculateCosmicHarmony() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (s_coalitions.empty()) return 1.0f;
    float totalHarmony = 0.0f;
    for (const auto& [id, coalition] : s_coalitions) {
        totalHarmony += coalition.cohesionIndex;
    }
    return totalHarmony / s_coalitions.size();
}

nlohmann::json UniversalCouncilEngine::GetUniversalMetrics() {
    std::lock_guard<std::mutex> lock(s_mutex);
    nlohmann::json metrics;
    metrics["domainCount"] = s_domains.size();
    metrics["mandateCount"] = s_mandates.size();
    metrics["coalitionCount"] = s_coalitions.size();
    metrics["directiveCount"] = s_directives.size();
    metrics["assemblyCount"] = s_assemblies.size();
    metrics["universalUnity"] = CalculateUniversalUnity();
    metrics["cosmicHarmony"] = CalculateCosmicHarmony();
    metrics["tickCount"] = s_tickCount;
    return metrics;
}

nlohmann::json UniversalCouncilEngine::GenerateUniversalReport() {
    nlohmann::json report;
    report["metrics"] = GetUniversalMetrics();
    report["domains"] = nlohmann::json::array();
    report["mandates"] = nlohmann::json::array();
    report["coalitions"] = nlohmann::json::array();
    
    for (const auto& domain : GetAllUniversalDomains()) {
        nlohmann::json d;
        d["id"] = domain.domainId;
        d["name"] = domain.name;
        d["regionCount"] = domain.memberRegions.size();
        d["unityIndex"] = domain.unityIndex;
        d["authorityLevel"] = domain.authorityLevel;
        report["domains"].push_back(d);
    }
    
    for (const auto& mandate : GetAllMandates()) {
        nlohmann::json m;
        m["id"] = mandate.mandateId;
        m["name"] = mandate.name;
        m["active"] = mandate.active;
        m["enforcementPriority"] = mandate.enforcementPriority;
        report["mandates"].push_back(m);
    }
    
    return report;
}

void UniversalCouncilEngine::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    s_tickCount++;
    
    for (auto& [id, domain] : s_domains) {
        domain.unityIndex *= 0.9999f;
        domain.unityIndex += 0.0001f;
        domain.authorityLevel *= 0.9999f;
        domain.authorityLevel += 0.0001f;
    }
    
    for (auto& [id, coalition] : s_coalitions) {
        coalition.cohesionIndex *= 0.9999f;
        coalition.cohesionIndex += 0.0001f;
    }
}

bool UniversalCouncilEngine::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}

} // namespace Universal
