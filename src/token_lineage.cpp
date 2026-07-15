#include "token_lineage.h"
#include <sstream>
#include <iomanip>
#include <algorithm>

namespace RawrXD {

TokenLineage& TokenLineage::instance() {
    static TokenLineage instance;
    return instance;
}

void TokenLineage::recordMint(uint64_t nonce, uint64_t parentNonce,
                               const std::string& minterId,
                               ExecutionCapability::Type type) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    LineageNode node;
    node.tokenNonce = nonce;
    node.parentNonce = parentNonce;
    node.mintedBy = minterId;
    node.type = type;
    
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
    node.timestamp = ss.str();
    
    m_nodes[nonce] = node;
    
    // Link to parent
    if (parentNonce != 0) {
        auto it = m_nodes.find(parentNonce);
        if (it != m_nodes.end()) {
            it->second.derivedTokens.push_back(nonce);
        }
    }
    
    fprintf(stderr, "[Lineage] Minted token %llx by %s\n", 
            (unsigned long long)nonce, minterId.c_str());
}

void TokenLineage::recordDelegation(uint64_t parentNonce, uint64_t childNonce,
                                   const std::string& granteeId) {
    recordMint(childNonce, parentNonce, granteeId, ExecutionCapability::Type::HYBRID);
}

void TokenLineage::recordExecution(uint64_t tokenNonce, const std::string& planHash,
                                  const std::string& executionId,
                                  bool success, int64_t latencyMs) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    ExecutionEdge edge;
    edge.tokenNonce = tokenNonce;
    edge.planHash = planHash;
    edge.executionId = executionId;
    edge.success = success;
    edge.latencyMs = latencyMs;
    
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
    edge.timestamp = ss.str();
    
    m_executions.push_back(edge);
}

void TokenLineage::recordRevocation(uint64_t nonce, const std::string& reason) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto it = m_nodes.find(nonce);
    if (it != m_nodes.end()) {
        it->second.revoked = true;
        it->second.revocationReason = reason;
        
        fprintf(stderr, "[Lineage] Revoked token %llx: %s\n",
                (unsigned long long)nonce, reason.c_str());
    }
}

std::vector<uint64_t> TokenLineage::getRevocationCascade(uint64_t nonce) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<uint64_t> cascade;
    
    std::function<void(uint64_t)> collect = [&](uint64_t n) {
        cascade.push_back(n);
        auto it = m_nodes.find(n);
        if (it != m_nodes.end()) {
            for (uint64_t child : it->second.derivedTokens) {
                collect(child);
            }
        }
    };
    
    collect(nonce);
    return cascade;
}

void TokenLineage::revokeSubtree(uint64_t rootNonce, const std::string& reason) {
    auto cascade = getRevocationCascade(rootNonce);
    for (uint64_t nonce : cascade) {
        recordRevocation(nonce, reason);
    }
}

std::string TokenLineage::exportLineageGraph() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::stringstream dot;
    dot << "digraph TokenLineage {\n";
    
    for (const auto& [nonce, node] : m_nodes) {
        dot << "  \"" << std::hex << nonce << "\" [label=\"";
        dot << "Token " << std::hex << nonce << "\\n";
        dot << "Type: " << (int)node.type << "\\n";
        dot << "By: " << node.mintedBy << "\\n";
        dot << "Revoked: " << (node.revoked ? "YES" : "no");
        dot << "\"";
        if (node.revoked) {
            dot << ",style=filled,color=red";
        }
        dot << "];\n";
        
        if (node.parentNonce != 0) {
            dot << "  \"" << std::hex << node.parentNonce << "\" -> \"" 
                << std::hex << nonce << "\";\n";
        }
    }
    
    dot << "}\n";
    return dot.str();
}

ScopedLineage::ScopedLineage(uint64_t tokenNonce, const std::string& operation)
    : m_nonce(tokenNonce), m_operation(operation), m_start(std::chrono::steady_clock::now()) {
}

ScopedLineage::~ScopedLineage() {
    auto end = std::chrono::steady_clock::now();
    auto latency = std::chrono::duration_cast<std::chrono::milliseconds>(end - m_start).count();
    
    TokenLineage::instance().recordExecution(
        m_nonce, "", m_operation, true, latency);
}

} // namespace RawrXD
