#pragma once

#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <nlohmann/json.hpp>

namespace RawrXD {
namespace Sovereign {
namespace Society {

struct ContractClause {
    std::string clauseId;
    std::string description;
    std::string obligation;
    std::string benefit;
    bool isMandatory;
    float weight;
};

struct AgentContract {
    std::string contractId;
    std::string agentId;
    std::vector<std::string> clauseIds;
    int64_t signedAt;
    int64_t expiresAt;
    bool isActive;
    float complianceScore;
};

struct ContractViolation {
    std::string violationId;
    std::string contractId;
    std::string clauseId;
    std::string description;
    int64_t timestamp;
    bool isResolved;
};

class SocialContract {
public:
    static void Init();
    static void OnTick();
    static bool IsAlive();

    static std::string CreateClause(const std::string& description, 
                                     const std::string& obligation,
                                     const std::string& benefit,
                                     bool isMandatory,
                                     float weight);
    static std::string ProposeContract(const std::string& agentId, 
                                          const std::vector<std::string>& clauseIds,
                                          int64_t durationMs);
    static bool SignContract(const std::string& contractId);
    static bool TerminateContract(const std::string& contractId);
    
    static void RecordViolation(const std::string& contractId, 
                                 const std::string& clauseId,
                                 const std::string& description);
    static bool ResolveViolation(const std::string& violationId);
    
    static void UpdateCompliance(const std::string& contractId, float delta);
    
    static nlohmann::json GetClause(const std::string& clauseId);
    static nlohmann::json GetClauses();
    static nlohmann::json GetContract(const std::string& contractId);
    static nlohmann::json GetAgentContracts(const std::string& agentId);
    static nlohmann::json GetViolations(const std::string& contractId);
    
    static nlohmann::json GetContractMetrics();
    static nlohmann::json GetComplianceReport();

private:
    static std::vector<ContractClause> s_clauses;
    static std::vector<AgentContract> s_contracts;
    static std::vector<ContractViolation> s_violations;
    static std::mutex s_mutex;
    static bool s_alive;
    
    static ContractClause* FindClause(const std::string& clauseId);
    static AgentContract* FindContract(const std::string& contractId);
    static ContractViolation* FindViolation(const std::string& violationId);
};

} // namespace Society
} // namespace Sovereign
} // namespace RawrXD
