#pragma once
#ifndef RAWRXD_TOKEN_LINEAGE_H
#define RAWRXD_TOKEN_LINEAGE_H

#include "execution_capability.h"
#include <map>
#include <vector>
#include <string>
#include <chrono>
#include <mutex>

namespace RawrXD {

// ============================================================================
// TOKEN LINEAGE GRAPH
// 
// Tracks provenance: TokenAuthority -> CapabilityGrant -> DerivedToken -> Execution
// Enables full audit reconstruction and authority chain rollback.
// ============================================================================

struct LineageNode {
    uint64_t tokenNonce;
    uint64_t parentNonce;  // 0 = root (TokenAuthority minted)
    std::string mintedBy;  // Component ID
    std::string timestamp;
    ExecutionCapability::Type type;
    bool revoked = false;
    std::string revocationReason;
    std::vector<uint64_t> derivedTokens;
};

struct ExecutionEdge {
    uint64_t tokenNonce;
    std::string planHash;
    std::string executionId;
    std::string timestamp;
    bool success;
    int64_t latencyMs;
};

// ============================================================================
// Lineage Tracker - Immutable provenance graph
// ============================================================================
class TokenLineage {
public:
    static TokenLineage& instance();

    // Record lineage events
    void recordMint(uint64_t nonce, uint64_t parentNonce, 
                    const std::string& minterId,
                    ExecutionCapability::Type type);
    
    void recordDelegation(uint64_t parentNonce, uint64_t childNonce,
                         const std::string& granteeId);
    
    void recordExecution(uint64_t tokenNonce, const std::string& planHash,
                        const std::string& executionId,
                        bool success, int64_t latencyMs);
    
    void recordRevocation(uint64_t nonce, const std::string& reason);

    // Query lineage
    std::vector<LineageNode> getProvenanceChain(uint64_t nonce) const;
    std::vector<LineageNode> getDerivedTokens(uint64_t nonce) const;
    std::vector<ExecutionEdge> getExecutionHistory(uint64_t nonce) const;
    
    // Rollback support
    std::vector<uint64_t> getRevocationCascade(uint64_t nonce) const;
    void revokeSubtree(uint64_t rootNonce, const std::string& reason);

    // Audit export
    std::string exportLineageGraph() const;
    std::string exportExecutionTraces() const;

private:
    TokenLineage() = default;
    
    mutable std::mutex m_mutex;
    std::map<uint64_t, LineageNode> m_nodes;
    std::vector<ExecutionEdge> m_executions;
};

// ============================================================================
// Scoped Lineage Recorder - RAII for automatic recording
// ============================================================================
class ScopedLineage {
public:
    ScopedLineage(uint64_t tokenNonce, const std::string& operation);
    ~ScopedLineage();

private:
    uint64_t m_nonce;
    std::string m_operation;
    std::chrono::steady_clock::time_point m_start;
};

} // namespace RawrXD

#endif // RAWRXD_TOKEN_LINEAGE_H
