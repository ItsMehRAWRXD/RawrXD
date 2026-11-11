// cluster_discovery.cpp
// Batch 14: Cluster Discovery and Service Registry
//
// Automatic discovery of worker nodes in a cluster
// Features: mDNS, multicast, service registry, health checks

#include <cstring>
#include <vector>
#include <map>
#include <set>
#include <memory>
#include <thread>
#include <mutex>
#include <chrono>
#include <functional>

namespace Benchmark {
namespace Distributed {

// Service information
struct ServiceInfo {
    std::string service_id;
    std::string service_type;
    std::string hostname;
    std::string address;
    int port;
    std::map<std::string, std::string> metadata;
    int64_t registered_at;
    int64_t last_seen;
    int ttl_seconds;
    bool healthy;
};

// Discovery configuration
struct DiscoveryConfig {
    std::string service_name = "benchmark-worker";
    std::string service_type = "_benchmark._tcp";
    int discovery_port = 5353;  // mDNS port
    int announcement_interval_ms = 30000;
    int cleanup_interval_ms = 60000;
    int service_ttl_seconds = 120;
    bool enable_multicast = true;
    std::string multicast_address = "224.0.0.251";
};

// Service registry
class ServiceRegistry {
public:
    explicit ServiceRegistry(const DiscoveryConfig& config = DiscoveryConfig())
        : config_(config), running_(false) {}

    ~ServiceRegistry() {
        Stop();
    }

    // Start registry
    bool Start() {
        if (running_) return true;

        running_ = true;

        // Start discovery listener
        listener_thread_ = std::thread(
            &ServiceRegistry::ListenerLoop, this);

        // Start cleanup thread
        cleanup_thread_ = std::thread(
            &ServiceRegistry::CleanupLoop, this);

        return true;
    }

    // Stop registry
    void Stop() {
        running_ = false;
        cv_.notify_all();

        if (listener_thread_.joinable()) listener_thread_.join();
        if (cleanup_thread_.joinable()) cleanup_thread_.join();
    }

    // Register local service
    bool RegisterService(const ServiceInfo& service) {
        std::lock_guard<std::mutex> lock(services_mutex_);

        services_[service.service_id] = service;
        return true;
    }

    // Unregister service
    bool UnregisterService(const std::string& service_id) {
        std::lock_guard<std::mutex> lock(services_mutex_);

        return services_.erase(service_id) > 0;
    }

    // Discover services by type
    std::vector<ServiceInfo> DiscoverServices(const std::string& service_type) {
        std::lock_guard<std::mutex> lock(services_mutex_);

        std::vector<ServiceInfo> result;
        for (const auto& [id, service] : services_) {
            if (service.service_type == service_type && service.healthy) {
                result.push_back(service);
            }
        }

        return result;
    }

    // Get service by ID
    std::optional<ServiceInfo> GetService(const std::string& service_id) {
        std::lock_guard<std::mutex> lock(services_mutex_);

        auto it = services_.find(service_id);
        if (it != services_.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    // Update service health
    bool UpdateHealth(const std::string& service_id, bool healthy) {
        std::lock_guard<std::mutex> lock(services_mutex_);

        auto it = services_.find(service_id);
        if (it != services_.end()) {
            it->second.healthy = healthy;
            it->second.last_seen = GetTimestamp();
            return true;
        }
        return false;
    }

    // Get all healthy services
    std::vector<ServiceInfo> GetHealthyServices() {
        std::lock_guard<std::mutex> lock(services_mutex_);

        std::vector<ServiceInfo> result;
        for (const auto& [id, service] : services_) {
            if (service.healthy) {
                result.push_back(service);
            }
        }

        return result;
    }

    // Watch for service changes
    using ServiceCallback = std::function<void(const ServiceInfo&, bool added)>;
    void WatchServices(ServiceCallback callback) {
        std::lock_guard<std::mutex> lock(callbacks_mutex_);
        callbacks_.push_back(callback);
    }

private:
    DiscoveryConfig config_;
    std::atomic<bool> running_;

    std::map<std::string, ServiceInfo> services_;
    mutable std::mutex services_mutex_;

    std::vector<ServiceCallback> callbacks_;
    mutable std::mutex callbacks_mutex_;

    std::thread listener_thread_;
    std::thread cleanup_thread_;
    std::condition_variable cv_;

    void ListenerLoop() {
        // In production: Implement mDNS/multicast listener
        while (running_) {
            // Listen for service announcements
            // Parse and add to registry

            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }

    void CleanupLoop() {
        while (running_) {
            std::this_thread::sleep_for(
                std::chrono::milliseconds(config_.cleanup_interval_ms));

            if (!running_) break;

            CleanupExpiredServices();
        }
    }

    void CleanupExpiredServices() {
        std::lock_guard<std::mutex> lock(services_mutex_);

        auto now = GetTimestamp();
        std::vector<std::string> expired;

        for (const auto& [id, service] : services_) {
            if (now - service.last_seen > service.ttl_seconds) {
                expired.push_back(id);
            }
        }

        for (const auto& id : expired) {
            services_.erase(id);
            NotifyCallbacks(services_[id], false);
        }
    }

    void NotifyCallbacks(const ServiceInfo& service, bool added) {
        std::lock_guard<std::mutex> lock(callbacks_mutex_);
        for (const auto& callback : callbacks_) {
            callback(service, added);
        }
    }

    int64_t GetTimestamp() {
        return std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }
};

// mDNS broadcaster
class MDNSBroadcaster {
public:
    explicit MDNSBroadcaster(const DiscoveryConfig& config = DiscoveryConfig())
        : config_(config), running_(false) {}

    ~MDNSBroadcaster() {
        Stop();
    }

    // Start broadcasting
    bool Start(const ServiceInfo& local_service) {
        if (running_) return true;

        local_service_ = local_service;
        running_ = true;

        broadcaster_thread_ = std::thread(
            &MDNSBroadcaster::BroadcastLoop, this);

        return true;
    }

    // Stop broadcasting
    void Stop() {
        running_ = false;

        if (broadcaster_thread_.joinable()) broadcaster_thread_.join();
    }

    // Update service info
    void UpdateService(const ServiceInfo& service) {
        local_service_ = service;
    }

private:
    DiscoveryConfig config_;
    std::atomic<bool> running_;
    ServiceInfo local_service_;
    std::thread broadcaster_thread_;

    void BroadcastLoop() {
        while (running_) {
            SendAnnouncement();

            std::this_thread::sleep_for(
                std::chrono::milliseconds(config_.announcement_interval_ms));
        }

        // Send goodbye message
        SendGoodbye();
    }

    void SendAnnouncement() {
        // In production: Implement mDNS announcement
        // Format: _benchmark._tcp.local. 120 IN SRV 0 0 9091 hostname.local.
    }

    void SendGoodbye() {
        // In production: Send mDNS goodbye (TTL=0)
    }
};

// Cluster manager
class ClusterManager {
public:
    struct ClusterConfig {
        bool auto_discovery = true;
        bool auto_join = true;
        std::vector<std::string> seed_nodes;
        int min_nodes = 1;
        int max_nodes = 100;
    };

    ClusterManager(const ClusterConfig& config = ClusterConfig())
        : config_(config), registry_(std::make_unique<ServiceRegistry>()),
          broadcaster_(std::make_unique<MDNSBroadcaster>()) {}

    // Initialize cluster
    bool Initialize(const ServiceInfo& local_service) {
        // Start service registry
        if (!registry_->Start()) {
            return false;
        }

        // Register local service
        registry_->RegisterService(local_service);

        // Start broadcasting if enabled
        if (config_.auto_discovery) {
            DiscoveryConfig discovery_config;
            broadcaster_ = std::make_unique<MDNSBroadcaster>(discovery_config);
            broadcaster_->Start(local_service);
        }

        // Join seed nodes
        if (config_.auto_join) {
            for (const auto& seed : config_.seed_nodes) {
                JoinNode(seed);
            }
        }

        // Watch for new services
        registry_->WatchServices([this](const ServiceInfo& service, bool added) {
            if (added) {
                OnNodeJoined(service);
            } else {
                OnNodeLeft(service);
            }
        });

        return true;
    }

    // Shutdown cluster
    void Shutdown() {
        if (broadcaster_) {
            broadcaster_->Stop();
        }

        registry_->Stop();
    }

    // Get cluster members
    std::vector<ServiceInfo> GetMembers() {
        return registry_->GetHealthyServices();
    }

    // Get cluster size
    size_t GetClusterSize() {
        return GetMembers().size();
    }

    // Check if cluster is ready
    bool IsReady() {
        return GetClusterSize() >= static_cast<size_t>(config_.min_nodes);
    }

    // Wait for cluster to be ready
    bool WaitForReady(int timeout_ms = 60000) {
        auto deadline = std::chrono::steady_clock::now() +
                       std::chrono::milliseconds(timeout_ms);

        while (std::chrono::steady_clock::now() < deadline) {
            if (IsReady()) {
                return true;
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        return false;
    }

private:
    ClusterConfig config_;
    std::unique_ptr<ServiceRegistry> registry_;
    std::unique_ptr<MDNSBroadcaster> broadcaster_;

    void JoinNode(const std::string& address) {
        // In production: Connect to seed node and sync registry
    }

    void OnNodeJoined(const ServiceInfo& service) {
        // Handle new node joining cluster
    }

    void OnNodeLeft(const ServiceInfo& service) {
        // Handle node leaving cluster
    }
};

} // namespace Distributed
} // namespace Benchmark
