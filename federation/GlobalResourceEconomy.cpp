#include "federation/GlobalResourceEconomy.hpp"
#include <mutex>
#include <map>
#include <chrono>

static std::mutex s_mutex;
static bool s_initialized = false;

static nlohmann::json s_localResources;
static std::map<std::string, nlohmann::json> s_clusterResources;
static size_t s_requestCount = 0;
static size_t s_offerCount = 0;

void GlobalResourceEconomy::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) {
        s_localResources = {
            {"cpu", 0.0},
            {"memory", 0.0},
            {"storage", 0.0}
        };
        s_clusterResources.clear();
        s_requestCount = 0;
        s_offerCount = 0;
        s_initialized = true;
    }
}

void GlobalResourceEconomy::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
}

bool GlobalResourceEconomy::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}

void GlobalResourceEconomy::UpdateLocalResources(const nlohmann::json& resources) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    s_localResources = resources;
}

void GlobalResourceEconomy::UpdateClusterResources(const std::string& clusterId, const nlohmann::json& resources) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    s_clusterResources[clusterId] = resources;
}

nlohmann::json GlobalResourceEconomy::GetLocalResources() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_localResources;
}

nlohmann::json GlobalResourceEconomy::GetClusterResources(const std::string& clusterId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    auto it = s_clusterResources.find(clusterId);
    if (it != s_clusterResources.end()) {
        return it->second;
    }
    return nlohmann::json{};
}

nlohmann::json GlobalResourceEconomy::GetGlobalResources() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    nlohmann::json result = nlohmann::json::object();
    result["local"] = s_localResources;
    
    nlohmann::json clusters = nlohmann::json::object();
    for (const auto& [id, resources] : s_clusterResources) {
        clusters[id] = resources;
    }
    result["clusters"] = clusters;
    
    return result;
}

nlohmann::json GlobalResourceEconomy::RequestResources(const std::string& fromCluster, double amount) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return nlohmann::json{};
    
    s_requestCount++;
    
    return {
        {"request_id", "req-" + std::to_string(s_requestCount)},
        {"from_cluster", fromCluster},
        {"amount_requested", amount},
        {"status", "pending"}
    };
}

nlohmann::json GlobalResourceEconomy::OfferResources(const std::string& toCluster, double amount) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return nlohmann::json{};
    
    s_offerCount++;
    
    return {
        {"offer_id", "off-" + std::to_string(s_offerCount)},
        {"to_cluster", toCluster},
        {"amount_offered", amount},
        {"status", "available"}
    };
}

nlohmann::json GlobalResourceEconomy::GetEconomyMetrics() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    return {
        {"local_resources", s_localResources},
        {"cluster_count", s_clusterResources.size()},
        {"total_requests", s_requestCount},
        {"total_offers", s_offerCount}
    };
}
