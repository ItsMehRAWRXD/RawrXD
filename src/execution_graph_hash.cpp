#include "execution_graph_hash.h"
#include <sstream>
#include <iomanip>
#include <openssl/evp.h>

namespace RawrXD {

// ============================================================================
// GraphHasher Implementation
// ============================================================================

NodeHash GraphHasher::hashNode(const AgenticTaskNode& node) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return NodeHash{};
    
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    
    // Hash node content (deterministic)
    std::string content = node.nodeType + ":" + node.state + ":" + node.intent;
    EVP_DigestUpdate(ctx, content.data(), content.size());
    
    // Hash collapse metadata if present
    if (node.collapsed) {
        std::string collapseInfo = "collapsed:" + 
            std::to_string(node.successCount) + ":" +
            std::to_string(node.failureCount);
        EVP_DigestUpdate(ctx, collapseInfo.data(), collapseInfo.size());
    }
    
    NodeHash hash;
    unsigned int len = 0;
    EVP_DigestFinal_ex(ctx, hash.data(), &len);
    EVP_MD_CTX_free(ctx);
    
    return hash;
}

GraphHash GraphHasher::hashGraph(const AgenticTaskNode& root) {
    std::map<std::string, NodeHash> cache;
    hashNodeRecursive(root, cache);
    
    // Combine all node hashes Merkle-style
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return GraphHash{};
    
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    
    for (const auto& [id, hash] : cache) {
        EVP_DigestUpdate(ctx, hash.data(), hash.size());
    }
    
    GraphHash result;
    unsigned int len = 0;
    EVP_DigestFinal_ex(ctx, result.data(), &len);
    EVP_MD_CTX_free(ctx);
    
    return result;
}

GraphHash GraphHasher::hashTopology(const AgenticTaskNode& root) {
    // Hash only structure, ignore timestamps/IDs
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return GraphHash{};
    
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    
    std::function<void(const AgenticTaskNode&)> hashTopo = 
        [&](const AgenticTaskNode& node) {
            std::string typeHash = node.nodeType + ":" + node.state;
            EVP_DigestUpdate(ctx, typeHash.data(), typeHash.size());
            
            for (const auto& child : node.children) {
                hashTopo(child);
            }
        };
    
    hashTopo(root);
    
    GraphHash result;
    unsigned int len = 0;
    EVP_DigestFinal_ex(ctx, result.data(), &len);
    EVP_MD_CTX_free(ctx);
    
    return result;
}

GraphHash GraphHasher::hashOutcome(const AgenticTaskNode& root) {
    // Hash results and outcomes
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return GraphHash{};
    
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    
    std::function<void(const AgenticTaskNode&)> hashResult = 
        [&](const AgenticTaskNode& node) {
            std::string outcome = node.state + ":" + 
                (node.result.empty() ? "null" : node.result);
            EVP_DigestUpdate(ctx, outcome.data(), outcome.size());
            
            for (const auto& child : node.children) {
                hashResult(child);
            }
        };
    
    hashResult(root);
    
    GraphHash result;
    unsigned int len = 0;
    EVP_DigestFinal_ex(ctx, result.data(), &len);
    EVP_MD_CTX_free(ctx);
    
    return result;
}

std::string GraphHasher::toHex(const NodeHash& hash) {
    std::stringstream ss;
    for (auto b : hash) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    }
    return ss.str();
}

std::string GraphHasher::toHex(const GraphHash& hash) {
    std::stringstream ss;
    for (auto b : hash) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    }
    return ss.str();
}

// ============================================================================
// GraphCache Implementation
// ============================================================================

GraphCache& GraphCache::instance() {
    static GraphCache cache;
    return cache;
}

void GraphCache::cacheSubgraph(const GraphHash& hash, const AgenticTaskNode& root) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_cache[hash] = root;
    m_accessTimes[hash] = std::chrono::steady_clock::now();
}

std::optional<AgenticTaskNode> GraphCache::retrieve(const GraphHash& hash) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_cache.find(hash);
    if (it != m_cache.end()) {
        m_accessTimes[hash] = std::chrono::steady_clock::now();
        return it->second;
    }
    return std::nullopt;
}

bool GraphCache::contains(const GraphHash& hash) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_cache.find(hash) != m_cache.end();
}

size_t GraphCache::size() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_cache.size();
}

void GraphCache::clear() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_cache.clear();
    m_accessTimes.clear();
}

void GraphCache::prune(size_t maxEntries) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_cache.size() <= maxEntries) return;
    
    // Sort by access time, remove oldest
    std::vector<std::pair<GraphHash, std::chrono::steady_clock::time_point>> entries(
        m_accessTimes.begin(), m_accessTimes.end());
    
    std::sort(entries.begin(), entries.end(), 
        [](const auto& a, const auto& b) { return a.second < b.second; });
    
    size_t toRemove = m_cache.size() - maxEntries;
    for (size_t i = 0; i < toRemove; ++i) {
        m_cache.erase(entries[i].first);
        m_accessTimes.erase(entries[i].first);
    }
}

// ============================================================================
// ReplayValidator Implementation
// ============================================================================

void ReplayValidator::recordExpected(const GraphHash& hash, const std::string& executionId) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_expectedHashes[executionId] = hash;
}

ReplayValidator::ValidationResult ReplayValidator::validate(
    const AgenticTaskNode& actualRoot, const std::string& executionId) {
    
    std::lock_guard<std::mutex> lock(m_mutex);
    ValidationResult result;
    
    auto it = m_expectedHashes.find(executionId);
    if (it == m_expectedHashes.end()) {
        result.divergences.push_back("No expected hash recorded for execution: " + executionId);
        return result;
    }
    
    GraphHash actualHash = GraphHasher::hashGraph(actualRoot);
    result.expectedHash = GraphHasher::toHex(it->second);
    result.actualHash = GraphHasher::toHex(actualHash);
    result.matches = GraphHasher::equal(it->second, actualHash);
    
    if (!result.matches) {
        result.divergences.push_back("Graph hash mismatch");
    }
    
    return result;
}

bool ReplayValidator::detectRegression(const GraphHash& current, const GraphHash& baseline) {
    return !GraphHasher::equal(current, baseline);
}

} // namespace RawrXD
