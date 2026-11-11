/**
 * ServiceDiscovery.hpp
 *
 * Phase N Batch 3/5: Service Discovery & Registry
 *
 * Service discovery with support for multiple backends, health checking,
 * and service mesh integration.
 */

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <optional>
#include <functional>
#include <chrono>

namespace Gateway {

// ============================================================================
// Forward Declarations
// ============================================================================

class ServiceInstance;
class ServiceRegistry;
class ServiceDiscovery;
class HealthChecker;

// ============================================================================
// Service Status
// ============================================================================

enum class ServiceStatus {
    UNKNOWN,
    STARTING,
    UP,
    DOWN,
    OUT_OF_SERVICE,
    WARNING
};

std::string ServiceStatusToString(ServiceStatus status);

// ============================================================================
// Service Instance
// ============================================================================

/**
 * Service instance information.
 */
class ServiceInstance {
public:
    struct Config {
        std::string instanceId;
        std::string serviceName;
        std::string host;
        uint16_t port;
        std::string protocol;  // http, https, grpc, tcp
        std::string version;
        std::map<std::string, std::string> metadata;
        std::map<std::string, std::string> tags;
        ServiceStatus status;
        std::chrono::system_clock::time_point registrationTime;
        std::chrono::system_clock::time_point lastHeartbeat;
        std::optional<std::chrono::seconds> leaseDuration;
        uint32_t weight;
        bool ephemeral;
    };
    
    explicit ServiceInstance(const Config& config);
    
    // Accessors
    const std::string& GetInstanceId() const { return config_.instanceId; }
    const std::string& GetServiceName() const { return config_.serviceName; }
    const std::string& GetHost() const { return config_.host; }
    uint16_t GetPort() const { return config_.port; }
    std::string GetAddress() const { return config_.host + ":" + std::to_string(config_.port); }
    const std::string& GetProtocol() const { return config_.protocol; }
    const std::string& GetVersion() const { return config_.version; }
    ServiceStatus GetStatus() const { return config_.status; }
    
    // Metadata
    void SetMetadata(const std::string& key, const std::string& value);
    std::optional<std::string> GetMetadata(const std::string& key) const;
    const std::map<std::string, std::string>& GetMetadata() const { return config_.metadata; }
    
    // Tags
    void AddTag(const std::string& tag);
    void RemoveTag(const std::string& tag);
    bool HasTag(const std::string& tag) const;
    const std::map<std::string, std::string>& GetTags() const { return config_.tags; }
    
    // Status
    void SetStatus(ServiceStatus status);
    bool IsHealthy() const { return config_.status == ServiceStatus::UP; }
    
    // Heartbeat
    void UpdateHeartbeat();
    std::chrono::seconds GetTimeSinceLastHeartbeat() const;
    bool IsExpired() const;
    
    // Weight
    void SetWeight(uint32_t weight);
    uint32_t GetWeight() const { return config_.weight; }
    
    // Comparison
    bool operator==(const ServiceInstance& other) const;
    bool operator<(const ServiceInstance& other) const;
    
    // Serialization
    std::string ToJson() const;
    static ServiceInstance FromJson(const std::string& json);
    
private:
    Config config_;
    mutable std::mutex mutex_;
};

// ============================================================================
// Service Query
// ============================================================================

/**
 * Query for service discovery.
 */
struct ServiceQuery {
    std::string serviceName;
    std::optional<std::string> version;
    std::optional<ServiceStatus> status;
    std::map<std::string, std::string> metadataFilter;
    std::vector<std::string> requiredTags;
    std::optional<std::string> protocol;
    bool healthyOnly;
    
    static ServiceQuery ByName(const std::string& name);
    static ServiceQuery ByVersion(const std::string& name, const std::string& version);
    static ServiceQuery Healthy(const std::string& name);
    
    ServiceQuery& WithVersion(const std::string& version);
    ServiceQuery& WithStatus(ServiceStatus status);
    ServiceQuery& WithMetadata(const std::string& key, const std::string& value);
    ServiceQuery& WithTag(const std::string& tag);
    ServiceQuery& WithProtocol(const std::string& protocol);
    ServiceQuery& OnlyHealthy();
};

// ============================================================================
// Service Registry
// ============================================================================

/**
 * Service registry interface.
 */
class ServiceRegistry {
public:
    virtual ~ServiceRegistry() = default;
    
    // Registration
    virtual bool Register(std::shared_ptr<ServiceInstance> instance) = 0;
    virtual bool Deregister(const std::string& instanceId) = 0;
    virtual bool Renew(const std::string& instanceId) = 0;
    
    // Discovery
    virtual std::vector<std::shared_ptr<ServiceInstance>> Query(
        const ServiceQuery& query) = 0;
    virtual std::optional<std::shared_ptr<ServiceInstance>> GetInstance(
        const std::string& instanceId) = 0;
    
    // Service management
    virtual std::vector<std::string> GetServiceNames() = 0;
    virtual std::vector<std::shared_ptr<ServiceInstance>> GetServiceInstances(
        const std::string& serviceName) = 0;
    virtual size_t GetServiceCount(const std::string& serviceName) = 0;
    
    // Health updates
    virtual bool UpdateStatus(const std::string& instanceId, ServiceStatus status) = 0;
    virtual bool UpdateMetadata(const std::string& instanceId,
                                   const std::map<std::string, std::string>& metadata) = 0;
    
    // Watch
    using ServiceCallback = std::function<void(const std::string& serviceName,
                                                   const std::vector<std::shared_ptr<ServiceInstance>>&)>;
    virtual std::string Watch(const std::string& serviceName, ServiceCallback callback) = 0;
    virtual bool Unwatch(const std::string& watchId) = 0;
    
    // Info
    virtual std::string GetName() const = 0;
};

/**
 * In-memory service registry.
 */
class InMemoryRegistry : public ServiceRegistry {
public:
    explicit InMemoryRegistry();
    
    bool Register(std::shared_ptr<ServiceInstance> instance) override;
    bool Deregister(const std::string& instanceId) override;
    bool Renew(const std::string& instanceId) override;
    
    std::vector<std::shared_ptr<ServiceInstance>> Query(
        const ServiceQuery& query) override;
    std::optional<std::shared_ptr<ServiceInstance>> GetInstance(
        const std::string& instanceId) override;
    
    std::vector<std::string> GetServiceNames() override;
    std::vector<std::shared_ptr<ServiceInstance>> GetServiceInstances(
        const std::string& serviceName) override;
    size_t GetServiceCount(const std::string& serviceName) override;
    
    bool UpdateStatus(const std::string& instanceId, ServiceStatus status) override;
    bool UpdateMetadata(const std::string& instanceId,
                        const std::map<std::string, std::string>& metadata) override;
    
    std::string Watch(const std::string& serviceName, ServiceCallback callback) override;
    bool Unwatch(const std::string& watchId) override;
    
    std::string GetName() const override { return "InMemoryRegistry"; }
    
    // Cleanup
    void CleanupExpired();
    
private:
    std::map<std::string, std::shared_ptr<ServiceInstance>> instances_;
    std::map<std::string, std::vector<std::shared_ptr<ServiceInstance>>> services_;
    std::map<std::string, std::pair<std::string, ServiceCallback>> watchers_;
    mutable std::mutex mutex_;
    uint64_t nextWatchId_;
    
    bool MatchesQuery(std::shared_ptr<ServiceInstance> instance, const ServiceQuery& query);
    void NotifyWatchers(const std::string& serviceName);
};

/**
 * Consul service registry.
 */
class ConsulRegistry : public ServiceRegistry {
public:
    struct Config {
        std::string host;
        uint16_t port;
        std::string datacenter;
        std::optional<std::string> token;
        std::chrono::seconds checkInterval;
        std::chrono::seconds deregisterAfter;
    };
    
    explicit ConsulRegistry(const Config& config);
    
    bool Connect();
    void Disconnect();
    bool IsConnected() const;
    
    bool Register(std::shared_ptr<ServiceInstance> instance) override;
    bool Deregister(const std::string& instanceId) override;
    bool Renew(const std::string& instanceId) override;
    
    std::vector<std::shared_ptr<ServiceInstance>> Query(
        const ServiceQuery& query) override;
    std::optional<std::shared_ptr<ServiceInstance>> GetInstance(
        const std::string& instanceId) override;
    
    std::vector<std::string> GetServiceNames() override;
    std::vector<std::shared_ptr<ServiceInstance>> GetServiceInstances(
        const std::string& serviceName) override;
    size_t GetServiceCount(const std::string& serviceName) override;
    
    bool UpdateStatus(const std::string& instanceId, ServiceStatus status) override;
    bool UpdateMetadata(const std::string& instanceId,
                        const std::map<std::string, std::string>& metadata) override;
    
    std::string Watch(const std::string& serviceName, ServiceCallback callback) override;
    bool Unwatch(const std::string& watchId) override;
    
    std::string GetName() const override { return "Consul"; }
    
private:
    Config config_;
    bool connected_;
    mutable std::mutex mutex_;
    
    std::string MakeServiceUrl() const;
    std::string MakeHealthUrl() const;
};

/**
 * etcd service registry.
 */
class EtcdRegistry : public ServiceRegistry {
public:
    struct Config {
        std::vector<std::string> endpoints;
        std::optional<std::string> username;
        std::optional<std::string> password;
        std::chrono::seconds ttl;
        std::string prefix;
    };
    
    explicit EtcdRegistry(const Config& config);
    
    bool Connect();
    void Disconnect();
    bool IsConnected() const;
    
    bool Register(std::shared_ptr<ServiceInstance> instance) override;
    bool Deregister(const std::string& instanceId) override;
    bool Renew(const std::string& instanceId) override;
    
    std::vector<std::shared_ptr<ServiceInstance>> Query(
        const ServiceQuery& query) override;
    std::optional<std::shared_ptr<ServiceInstance>> GetInstance(
        const std::string& instanceId) override;
    
    std::vector<std::string> GetServiceNames() override;
    std::vector<std::shared_ptr<ServiceInstance>> GetServiceInstances(
        const std::string& serviceName) override;
    size_t GetServiceCount(const std::string& serviceName) override;
    
    bool UpdateStatus(const std::string& instanceId, ServiceStatus status) override;
    bool UpdateMetadata(const std::string& instanceId,
                        const std::map<std::string, std::string>& metadata) override;
    
    std::string Watch(const std::string& serviceName, ServiceCallback callback) override;
    bool Unwatch(const std::string& watchId) override;
    
    std::string GetName() const override { return "etcd"; }
    
private:
    Config config_;
    bool connected_;
    void* etcdClient_;
    mutable std::mutex mutex_;
    
    std::string MakeKey(const std::string& serviceName,
                        const std::string& instanceId) const;
};

/**
 * Kubernetes service registry.
 */
class KubernetesRegistry : public ServiceRegistry {
public:
    struct Config {
        std::string apiServer;
        std::string token;
        std::string namespace_;
        std::optional<std::string> caCert;
        bool useInClusterConfig;
    };
    
    explicit KubernetesRegistry(const Config& config);
    
    bool Connect();
    void Disconnect();
    bool IsConnected() const;
    
    bool Register(std::shared_ptr<ServiceInstance> instance) override;
    bool Deregister(const std::string& instanceId) override;
    bool Renew(const std::string& instanceId) override;
    
    std::vector<std::shared_ptr<ServiceInstance>> Query(
        const ServiceQuery& query) override;
    std::optional<std::shared_ptr<ServiceInstance>> GetInstance(
        const std::string& instanceId) override;
    
    std::vector<std::string> GetServiceNames() override;
    std::vector<std::shared_ptr<ServiceInstance>> GetServiceInstances(
        const std::string& serviceName) override;
    size_t GetServiceCount(const std::string& serviceName) override;
    
    bool UpdateStatus(const std::string& instanceId, ServiceStatus status) override;
    bool UpdateMetadata(const std::string& instanceId,
                        const std::map<std::string, std::string>& metadata) override;
    
    std::string Watch(const std::string& serviceName, ServiceCallback callback) override;
    bool Unwatch(const std::string& watchId) override;
    
    std::string GetName() const override { return "Kubernetes"; }
    
private:
    Config config_;
    bool connected_;
    void* k8sClient_;
    mutable std::mutex mutex_;
};

// ============================================================================
// Health Checker
// ============================================================================

/**
 * Service health checker.
 */
class HealthChecker {
public:
    struct Config {
        std::chrono::seconds checkInterval;
        std::chrono::seconds timeout;
        uint32_t consecutiveFailuresThreshold;
        uint32_t consecutiveSuccessesThreshold;
        bool enabled;
    };
    
    struct HealthCheck {
        std::string instanceId;
        std::string endpoint;
        std::string protocol;  // http, tcp, grpc
        std::map<std::string, std::string> headers;
        std::optional<std::string> expectedResponse;
        std::chrono::seconds interval;
    };
    
    explicit HealthChecker(const Config& config,
                           std::shared_ptr<ServiceRegistry> registry);
    
    // Lifecycle
    void Start();
    void Stop();
    bool IsRunning() const;
    
    // Health check registration
    void RegisterCheck(const HealthCheck& check);
    void UnregisterCheck(const std::string& instanceId);
    
    // Manual check
    ServiceStatus CheckHealth(const std::string& instanceId);
    ServiceStatus CheckHealth(std::shared_ptr<ServiceInstance> instance);
    
    // Statistics
    struct CheckerStats {
        uint64_t checksPerformed;
        uint64_t checksPassed;
        uint64_t checksFailed;
        uint64_t statusChanges;
        double averageCheckTimeMs;
    };
    CheckerStats GetStats() const;
    
private:
    Config config_;
    std::shared_ptr<ServiceRegistry> registry_;
    std::atomic<bool> running_;
    std::map<std::string, HealthCheck> checks_;
    std::map<std::string, uint32_t> consecutiveFailures_;
    std::map<std::string, uint32_t> consecutiveSuccesses_;
    mutable std::mutex mutex_;
    
    CheckerStats stats_;
    mutable std::mutex statsMutex_;
    
    std::thread checkThread_;
    
    void CheckLoop();
    ServiceStatus PerformCheck(const HealthCheck& check);
    ServiceStatus PerformHttpCheck(const HealthCheck& check);
    ServiceStatus PerformTcpCheck(const HealthCheck& check);
    ServiceStatus PerformGrpcCheck(const HealthCheck& check);
};

// ============================================================================
// Service Discovery
// ============================================================================

/**
 * Central service discovery.
 */
class ServiceDiscovery {
public:
    struct Config {
        std::shared_ptr<ServiceRegistry> registry;
        std::optional<std::shared_ptr<HealthChecker>> healthChecker;
        bool enableCaching;
        std::chrono::seconds cacheTtl;
        bool enableLoadBalancing;
    };
    
    explicit ServiceDiscovery(const Config& config);
    ~ServiceDiscovery();
    
    // Initialization
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const;
    
    // Service registration
    bool Register(std::shared_ptr<ServiceInstance> instance);
    bool Deregister(const std::string& instanceId);
    bool Renew(const std::string& instanceId);
    
    // Service discovery
    std::vector<std::shared_ptr<ServiceInstance>> Discover(const std::string& serviceName);
    std::vector<std::shared_ptr<ServiceInstance>> Discover(const ServiceQuery& query);
    std::optional<std::shared_ptr<ServiceInstance>> GetInstance(
        const std::string& instanceId);
    
    // Load balancing
    std::optional<std::shared_ptr<ServiceInstance>> SelectInstance(
        const std::string& serviceName);
    std::optional<std::shared_ptr<ServiceInstance>> SelectInstance(
        const std::string& serviceName, const std::string& clientId);
    
    // Service info
    std::vector<std::string> GetServiceNames() const;
    size_t GetServiceCount(const std::string& serviceName) const;
    bool IsServiceHealthy(const std::string& serviceName) const;
    
    // Watch
    std::string Watch(const std::string& serviceName,
                      ServiceRegistry::ServiceCallback callback);
    bool Unwatch(const std::string& watchId);
    
    // Circuit breaker integration
    void MarkInstanceFailed(const std::string& instanceId);
    void MarkInstanceSuccess(const std::string& instanceId);
    bool IsInstanceAvailable(const std::string& instanceId) const;
    
    // Statistics
    struct DiscoveryStats {
        uint64_t registrations;
        uint64_t deregistrations;
        uint64_t discoveries;
        uint64_t cacheHits;
        uint64_t cacheMisses;
        double cacheHitRate;
    };
    DiscoveryStats GetStats() const;
    void ResetStats();
    
    // Health check
    bool HealthCheck() const;
    
private:
    Config config_;
    bool initialized_;
    
    // Cache
    struct CacheEntry {
        std::vector<std::shared_ptr<ServiceInstance>> instances;
        std::chrono::system_clock::time_point expiresAt;
    };
    std::map<std::string, CacheEntry> cache_;
    mutable std::mutex cacheMutex_;
    
    // Circuit breaker state
    struct CircuitState {
        uint32_t failures;
        uint32_t successes;
        bool open;
        std::chrono::system_clock::time_point lastFailure;
    };
    std::map<std::string, CircuitState> circuitStates_;
    mutable std::mutex circuitMutex_;
    
    DiscoveryStats stats_;
    mutable std::mutex statsMutex_;
    
    std::atomic<size_t> roundRobinIndex_;
    
    std::vector<std::shared_ptr<ServiceInstance>> GetFromCache(const std::string& serviceName);
    void UpdateCache(const std::string& serviceName,
                     const std::vector<std::shared_ptr<ServiceInstance>>& instances);
    void CleanupCache();
};

// ============================================================================
// Service Discovery Client
// ============================================================================

/**
 * Client for service discovery.
 */
class ServiceDiscoveryClient {
public:
    struct Config {
        std::string serviceName;
        std::string instanceId;
        std::string host;
        uint16_t port;
        std::string protocol;
        std::string version;
        std::map<std::string, std::string> metadata;
        std::map<std::string, std::string> tags;
        std::chrono::seconds heartbeatInterval;
        std::chrono::seconds leaseDuration;
    };
    
    explicit ServiceDiscoveryClient(const Config& config,
                                     std::shared_ptr<ServiceDiscovery> discovery);
    
    // Lifecycle
    bool Start();
    void Stop();
    bool IsRunning() const;
    
    // Registration
    bool Register();
    bool Deregister();
    
    // Heartbeat
    void SendHeartbeat();
    
    // Status
    void UpdateStatus(ServiceStatus status);
    void UpdateMetadata(const std::map<std::string, std::string>& metadata);
    
    // Discovery
    std::vector<std::shared_ptr<ServiceInstance>> Discover(const std::string& serviceName);
    std::optional<std::shared_ptr<ServiceInstance>> DiscoverOne(
        const std::string& serviceName);
    
private:
    Config config_;
    std::shared_ptr<ServiceDiscovery> discovery_;
    std::atomic<bool> running_;
    std::atomic<bool> registered_;
    
    std::thread heartbeatThread_;
    
    void HeartbeatLoop();
};

} // namespace Gateway
