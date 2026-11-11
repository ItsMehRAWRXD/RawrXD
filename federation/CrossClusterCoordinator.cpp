#include "federation/CrossClusterCoordinator.hpp"
#include <mutex>
#include <map>
#include <chrono>

static std::mutex s_mutex;
static bool s_initialized = false;

struct SyncStatus {
    std::string clusterId;
    int64_t lastSync;
    bool synced;
    nlohmann::json lastState;
};

static std::map<std::string, SyncStatus> s_syncStatus;
static size_t s_syncCount = 0;
static size_t s_broadcastCount = 0;

void CrossClusterCoordinator::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) {
        s_syncStatus.clear();
        s_syncCount = 0;
        s_broadcastCount = 0;
        s_initialized = true;
    }
}

void CrossClusterCoordinator::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    // Periodic sync checks
    auto now = std::chrono::system_clock::now().time_since_epoch().count();
    for (auto& [id, status] : s_syncStatus) {
        if ((now - status.lastSync) > 60000000000) { // 60 seconds
            status.synced = false;
        }
    }
}

bool CrossClusterCoordinator::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}

void CrossClusterCoordinator::Sync(const std::string& clusterId, const nlohmann::json& state) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    s_syncCount++;
    
    SyncStatus status;
    status.clusterId = clusterId;
    status.lastSync = std::chrono::system_clock::now().time_since_epoch().count();
    status.synced = true;
    status.lastState = state;
    
    s_syncStatus[clusterId] = status;
}

nlohmann::json CrossClusterCoordinator::GetSyncStatus(const std::string& clusterId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    auto it = s_syncStatus.find(clusterId);
    if (it != s_syncStatus.end()) {
        return {
            {"cluster_id", it->second.clusterId},
            {"last_sync", it->second.lastSync},
            {"synced", it->second.synced}
        };
    }
    return nlohmann::json{};
}

nlohmann::json CrossClusterCoordinator::GetAllSyncStatus() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    nlohmann::json result = nlohmann::json::object();
    for (const auto& [id, status] : s_syncStatus) {
        result[id] = {
            {"last_sync", status.lastSync},
            {"synced", status.synced}
        };
    }
    return result;
}

void CrossClusterCoordinator::BroadcastState(const nlohmann::json& state) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    s_broadcastCount++;
    // In a real implementation, this would broadcast to all clusters
    (void)state;
}

nlohmann::json CrossClusterCoordinator::ReceiveState(const std::string& fromCluster, const nlohmann::json& state) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return nlohmann::json{};
    
    SyncStatus status;
    status.clusterId = fromCluster;
    status.lastSync = std::chrono::system_clock::now().time_since_epoch().count();
    status.synced = true;
    status.lastState = state;
    
    s_syncStatus[fromCluster] = status;
    
    return {
        {"received", true},
        {"from_cluster", fromCluster},
        {"timestamp", status.lastSync}
    };
}

nlohmann::json CrossClusterCoordinator::GetCoordinationMetrics() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    size_t syncedCount = 0;
    for (const auto& [id, status] : s_syncStatus) {
        if (status.synced) syncedCount++;
    }
    
    return {
        {"total_clusters", s_syncStatus.size()},
        {"synced_clusters", syncedCount},
        {"total_syncs", s_syncCount},
        {"total_broadcasts", s_broadcastCount}
    };
}
