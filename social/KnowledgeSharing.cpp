#include "social/KnowledgeSharing.hpp"
#include <mutex>
#include <vector>
#include <map>

static std::mutex s_mutex;
static bool s_initialized = false;
static std::map<std::string, std::vector<nlohmann::json>> s_agentKnowledge;
static std::vector<nlohmann::json> s_knowledgePool;
static size_t s_shareCount = 0;
static size_t s_requestCount = 0;

void KnowledgeSharing::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) {
        s_agentKnowledge.clear();
        s_knowledgePool.clear();
        s_shareCount = 0;
        s_requestCount = 0;
        s_initialized = true;
    }
}

void KnowledgeSharing::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    // Process knowledge pool updates
    // In a real implementation, this would sync with other agents
}

bool KnowledgeSharing::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}

void KnowledgeSharing::ShareKnowledge(const std::string& agentId, const nlohmann::json& knowledge) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    nlohmann::json entry = {
        {"source", agentId},
        {"knowledge", knowledge},
        {"shared_at", std::chrono::system_clock::now().time_since_epoch().count()},
        {"verified", false}
    };
    
    s_agentKnowledge[agentId].push_back(entry);
    s_knowledgePool.push_back(entry);
    s_shareCount++;
}

void KnowledgeSharing::RequestKnowledge(const std::string& agentId, const std::string& topic) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    s_requestCount++;
    // In a real implementation, this would query other agents
}

nlohmann::json KnowledgeSharing::GetSharedKnowledge(const std::string& agentId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_agentKnowledge.find(agentId);
    if (it != s_agentKnowledge.end()) {
        return it->second;
    }
    return nlohmann::json::array();
}

nlohmann::json KnowledgeSharing::GetKnowledgePool() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_knowledgePool;
}

void KnowledgeSharing::ContributeToPool(const nlohmann::json& knowledge) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    nlohmann::json entry = {
        {"knowledge", knowledge},
        {"contributed_at", std::chrono::system_clock::now().time_since_epoch().count()},
        {"local", true}
    };
    
    s_knowledgePool.push_back(entry);
    if (s_knowledgePool.size() > 1000) {
        s_knowledgePool.erase(s_knowledgePool.begin());
    }
}

nlohmann::json KnowledgeSharing::QueryPool(const std::string& query) {
    std::lock_guard<std::mutex> lock(s_mutex);
    nlohmann::json results = nlohmann::json::array();
    
    for (const auto& entry : s_knowledgePool) {
        // Simple string matching
        std::string knowledgeStr = entry.dump();
        if (knowledgeStr.find(query) != std::string::npos) {
            results.push_back(entry);
        }
    }
    
    return results;
}

nlohmann::json KnowledgeSharing::GetSharingMetrics() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return {
        {"shares", s_shareCount},
        {"requests", s_requestCount},
        {"pool_size", s_knowledgePool.size()},
        {"active_agents", s_agentKnowledge.size()}
    };
}
