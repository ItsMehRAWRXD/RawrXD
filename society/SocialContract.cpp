#include "society/SocialContract.hpp"
#include <chrono>
#include <algorithm>

namespace RawrXD {
namespace Sovereign {
namespace Society {

std::vector<ContractClause> SocialContract::s_clauses;
std::vector<AgentContract> SocialContract::s_contracts;
std::vector<ContractViolation> SocialContract::s_violations;
std::mutex SocialContract::s_mutex;
bool SocialContract::s_alive = false;

void SocialContract::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    s_clauses.clear();
    s_contracts.clear();
    s_violations.clear();
    s_alive = true;
}

void SocialContract::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_alive) return;
    
    auto now = std::chrono::steady_clock::now().time_since_epoch().count();
    
    // Check for expired contracts
    for (auto& contract : s_contracts) {
        if (contract.isActive && now > contract.expiresAt) {
            contract.isActive = false;
        }
    }
}

bool SocialContract::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_alive;
}

std::string SocialContract::CreateClause(const std::string& description, 
                                          const std::string& obligation,
                                          const std::string& benefit,
                                          bool isMandatory,
                                          float weight) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    ContractClause clause;
    clause.clauseId = "clause_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    clause.description = description;
    clause.obligation = obligation;
    clause.benefit = benefit;
    clause.isMandatory = isMandatory;
    clause.weight = weight;
    
    s_clauses.push_back(clause);
    return clause.clauseId;
}

std::string SocialContract::ProposeContract(const std::string& agentId, 
                                             const std::vector<std::string>& clauseIds,
                                             int64_t durationMs) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    AgentContract contract;
    contract.contractId = "contract_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    contract.agentId = agentId;
    contract.clauseIds = clauseIds;
    contract.signedAt = std::chrono::steady_clock::now().time_since_epoch().count();
    contract.expiresAt = contract.signedAt + durationMs;
    contract.isActive = true;
    contract.complianceScore = 1.0f;
    
    s_contracts.push_back(contract);
    return contract.contractId;
}

bool SocialContract::SignContract(const std::string& contractId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    AgentContract* contract = FindContract(contractId);
    if (!contract) return false;
    
    contract->isActive = true;
    return true;
}

bool SocialContract::TerminateContract(const std::string& contractId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    AgentContract* contract = FindContract(contractId);
    if (!contract) return false;
    
    contract->isActive = false;
    return true;
}

void SocialContract::RecordViolation(const std::string& contractId, 
                                    const std::string& clauseId,
                                    const std::string& description) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    ContractViolation violation;
    violation.violationId = "violation_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    violation.contractId = contractId;
    violation.clauseId = clauseId;
    violation.description = description;
    violation.timestamp = std::chrono::steady_clock::now().time_since_epoch().count();
    violation.isResolved = false;
    
    s_violations.push_back(violation);
    
    // Update compliance score
    AgentContract* contract = FindContract(contractId);
    if (contract) {
        contract->complianceScore = std::max(0.0f, contract->complianceScore - 0.1f);
    }
}

bool SocialContract::ResolveViolation(const std::string& violationId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    ContractViolation* violation = FindViolation(violationId);
    if (!violation) return false;
    
    violation->isResolved = true;
    
    // Restore some compliance score
    AgentContract* contract = FindContract(violation->contractId);
    if (contract) {
        contract->complianceScore = std::min(1.0f, contract->complianceScore + 0.05f);
    }
    
    return true;
}

void SocialContract::UpdateCompliance(const std::string& contractId, float delta) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    AgentContract* contract = FindContract(contractId);
    if (!contract) return;
    
    contract->complianceScore = std::max(0.0f, std::min(1.0f, contract->complianceScore + delta));
}

nlohmann::json SocialContract::GetClause(const std::string& clauseId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    ContractClause* clause = FindClause(clauseId);
    if (!clause) return nlohmann::json{{"error", "clause not found"}};
    
    nlohmann::json j;
    j["clauseId"] = clause->clauseId;
    j["description"] = clause->description;
    j["obligation"] = clause->obligation;
    j["benefit"] = clause->benefit;
    j["isMandatory"] = clause->isMandatory;
    j["weight"] = clause->weight;
    return j;
}

nlohmann::json SocialContract::GetClauses() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    nlohmann::json clauses = nlohmann::json::array();
    for (const auto& clause : s_clauses) {
        nlohmann::json j;
        j["clauseId"] = clause.clauseId;
        j["description"] = clause.description;
        j["isMandatory"] = clause.isMandatory;
        j["weight"] = clause.weight;
        clauses.push_back(j);
    }
    return clauses;
}

nlohmann::json SocialContract::GetContract(const std::string& contractId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    AgentContract* contract = FindContract(contractId);
    if (!contract) return nlohmann::json{{"error", "contract not found"}};
    
    nlohmann::json j;
    j["contractId"] = contract->contractId;
    j["agentId"] = contract->agentId;
    j["clauseIds"] = contract->clauseIds;
    j["signedAt"] = contract->signedAt;
    j["expiresAt"] = contract->expiresAt;
    j["isActive"] = contract->isActive;
    j["complianceScore"] = contract->complianceScore;
    return j;
}

nlohmann::json SocialContract::GetAgentContracts(const std::string& agentId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    nlohmann::json contracts = nlohmann::json::array();
    for (const auto& contract : s_contracts) {
        if (contract.agentId == agentId) {
            nlohmann::json j;
            j["contractId"] = contract.contractId;
            j["isActive"] = contract.isActive;
            j["complianceScore"] = contract.complianceScore;
            j["expiresAt"] = contract.expiresAt;
            contracts.push_back(j);
        }
    }
    return contracts;
}

nlohmann::json SocialContract::GetViolations(const std::string& contractId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    nlohmann::json violations = nlohmann::json::array();
    for (const auto& violation : s_violations) {
        if (violation.contractId == contractId) {
            nlohmann::json j;
            j["violationId"] = violation.violationId;
            j["clauseId"] = violation.clauseId;
            j["description"] = violation.description;
            j["timestamp"] = violation.timestamp;
            j["isResolved"] = violation.isResolved;
            violations.push_back(j);
        }
    }
    return violations;
}

nlohmann::json SocialContract::GetContractMetrics() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    nlohmann::json metrics;
    metrics["totalClauses"] = s_clauses.size();
    metrics["totalContracts"] = s_contracts.size();
    
    size_t activeContracts = 0;
    float avgCompliance = 0.0f;
    for (const auto& contract : s_contracts) {
        if (contract.isActive) activeContracts++;
        avgCompliance += contract.complianceScore;
    }
    
    metrics["activeContracts"] = activeContracts;
    metrics["averageCompliance"] = s_contracts.empty() ? 0.0f : avgCompliance / s_contracts.size();
    
    size_t unresolvedViolations = 0;
    for (const auto& violation : s_violations) {
        if (!violation.isResolved) unresolvedViolations++;
    }
    metrics["unresolvedViolations"] = unresolvedViolations;
    
    return metrics;
}

nlohmann::json SocialContract::GetComplianceReport() {
    return GetContractMetrics();
}

ContractClause* SocialContract::FindClause(const std::string& clauseId) {
    for (auto& clause : s_clauses) {
        if (clause.clauseId == clauseId) return &clause;
    }
    return nullptr;
}

AgentContract* SocialContract::FindContract(const std::string& contractId) {
    for (auto& contract : s_contracts) {
        if (contract.contractId == contractId) return &contract;
    }
    return nullptr;
}

ContractViolation* SocialContract::FindViolation(const std::string& violationId) {
    for (auto& violation : s_violations) {
        if (violation.violationId == violationId) return &violation;
    }
    return nullptr;
}

} // namespace Society
} // namespace Sovereign
} // namespace RawrXD
