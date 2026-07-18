/**
 * ServiceMesh.hpp
 *
 * Phase N Batch 5/5: Service Mesh & Traffic Management
 *
 * Service mesh implementation with sidecar proxy, mTLS, traffic management,
 * and observability for microservices communication.
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

class SidecarProxy;
class TrafficManager;
class MutualTLS;
class ServiceMesh;

// ============================================================================
// Proxy Configuration
// ============================================================================

/**
 * Sidecar proxy configuration.
 */
struct ProxyConfig {
    std::string serviceName;
    std::string instanceId;
    std::string bindAddress;
    uint16_t inboundPort;
    uint16_t outboundPort;
    uint16_t adminPort;
    
    // Features
    bool enableMtls;
    bool enableRetry;
    bool enableCircuitBreaker;
    bool enableRateLimit;
    bool enableAccessLog;
    bool enableMetrics;
    bool enableTracing;
    
    // Timeouts
    std::chrono::milliseconds connectTimeout;
    std::chrono::milliseconds requestTimeout;
    std::chrono::milliseconds idleTimeout;
    
    // Connection pool
    uint32_t maxConnections;
    uint32_t maxPendingRequests;
    uint32_t maxRequestsPerConnection;
    
    // Discovery
    std::string discoveryServiceUrl;
    std::chrono::seconds discoveryRefreshInterval;
    
    // Admin
    std::string adminBindAddress;
};

// ============================================================================
// Traffic Policy
// ============================================================================

/**
 * Traffic routing policy.
 */
struct TrafficPolicy {
    enum class Type {
        ROUND_ROBIN,
        LEAST_REQUEST,
        RING_HASH,
        MAGLEV,
        RANDOM
    };
    
    std::string name;
    Type type;
    std::map<std::string, std::string> matchConditions;
    std::vector<std::string> targetServices;
    std::map<std::string, uint32_t> weights;
    
    // Retry policy
    uint32_t retryAttempts;
    std::chrono::milliseconds retryTimeout;
    std::vector<std::string> retryOn;
    
    // Timeout
    std::chrono::milliseconds requestTimeout;
    std::chrono::milliseconds idleTimeout;
    
    // Circuit breaker
    uint32_t maxConnections;
    uint32_t maxPendingRequests;
    uint32_t maxRequests;
    uint32_t maxRetries;
    
    // Outlier detection
    bool outlierDetection;
    uint32_t consecutiveErrors;
    std::chrono::milliseconds interval;
    std::chrono::milliseconds baseEjectionTime;
    
    static TrafficPolicy RoundRobin(const std::string& name);
    static TrafficPolicy Weighted(const std::string& name,
                                   const std::map<std::string, uint32_t>& weights);
    static TrafficPolicy Canary(const std::string& name,
                                 const std::string& stableVersion,
                                 const std::string& canaryVersion,
                                 uint32_t canaryPercent);
};

// ============================================================================
// Sidecar Proxy
// ============================================================================

/**
 * Sidecar proxy for service mesh.
 */
class SidecarProxy {
public:
    explicit SidecarProxy(const ProxyConfig& config);
    ~SidecarProxy();
    
    // Lifecycle
    bool Initialize();
    void Start();
    void Stop();
    bool IsRunning() const;
    
    // Configuration
    void UpdateConfig(const ProxyConfig& config);
    ProxyConfig GetConfig() const;
    
    // Traffic management
    void AddTrafficPolicy(const TrafficPolicy& policy);
    void RemoveTrafficPolicy(const std::string& name);
    std::vector<TrafficPolicy> GetTrafficPolicies() const;
    
    // Service registration
    void RegisterLocalService(const std::string& host, uint16_t port);
    void DeregisterLocalService();
    
    // Connection handling
    void HandleInboundConnection(int clientSocket);
    void HandleOutboundConnection(const std::string& serviceName, int clientSocket);
    
    // Statistics
    struct ProxyStats {
        uint64_t connectionsAccepted;
        uint64_t connectionsActive;
        uint64_t requestsTotal;
        uint64_t requestsSuccess;
        uint64_t requestsFailed;
        double requestDurationMs;
        uint64_t bytesReceived;
        uint64_t bytesSent;
    };
    ProxyStats GetStats() const;
    void ResetStats();
    
    // Admin interface
    std::string GetAdminStats() const;
    bool DrainConnections();
    void SetMaintenanceMode(bool enabled);
    
private:
    ProxyConfig config_;
    std::atomic<bool> running_;
    std::atomic<bool> maintenanceMode_;
    
    std::vector<TrafficPolicy> trafficPolicies_;
    mutable std::mutex policiesMutex_;
    
    ProxyStats stats_;
    mutable std::mutex statsMutex_;
    
    std::thread inboundThread_;
    std::thread outboundThread_;
    std::thread adminThread_;
    
    int inboundSocket_;
    int outboundSocket_;
    int adminSocket_;
    
    void InboundLoop();
    void OutboundLoop();
    void AdminLoop();
    void ProxyConnection(int sourceSocket, int destSocket);
    std::optional<std::pair<std::string, uint16_t>> ResolveService(
        const std::string& serviceName);
};

// ============================================================================
// Mutual TLS
// ============================================================================

/**
 * Mutual TLS for service-to-service authentication.
 */
class MutualTLS {
public:
    struct Config {
        std::string certChainFile;
        std::string privateKeyFile;
        std::string caCertFile;
        std::string crlFile;
        bool verifyClientCert;
        bool requireClientCert;
        std::vector<std::string> trustedDnsNames;
        std::vector<std::string> trustedUriIdentities;
        std::chrono::seconds certRefreshInterval;
    };
    
    struct CertificateInfo {
        std::string subject;
        std::string issuer;
        std::string serialNumber;
        std::chrono::system_clock::time_point notBefore;
        std::chrono::system_clock::time_point notAfter;
        std::vector<std::string> sanDnsNames;
        std::vector<std::string> sanUriIdentities;
        bool isCa;
    };
    
    explicit MutualTLS(const Config& config);
    ~MutualTLS();
    
    // Initialization
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const;
    
    // TLS context
    void* GetServerContext();  // Returns SSL_CTX*
    void* GetClientContext();    // Returns SSL_CTX*
    
    // Certificate validation
    bool ValidateCertificate(void* ssl);  // Takes SSL*
    std::optional<CertificateInfo> GetPeerCertificate(void* ssl);
    
    // Identity extraction
    std::optional<std::string> GetPeerIdentity(void* ssl);
    std::optional<std::string> GetPeerServiceName(void* ssl);
    
    // Certificate management
    bool ReloadCertificates();
    CertificateInfo GetLocalCertificate() const;
    std::vector<CertificateInfo> GetTrustedCAs() const;
    
    // SPIFFE/SPIRE integration
    void EnableSpiffe(bool enable);
    bool ValidateSpiffeId(const std::string& spiffeId);
    std::optional<std::string> ExtractSpiffeId(void* ssl);
    
    // Statistics
    struct MtlsStats {
        uint64_t handshakesCompleted;
        uint64_t handshakesFailed;
        uint64_t certificatesValidated;
        uint64_t certificatesRejected;
        std::chrono::system_clock::time_point lastCertRefresh;
    };
    MtlsStats GetStats() const;
    
private:
    Config config_;
    bool initialized_;
    void* serverContext_;
    void* clientContext_;
    mutable std::mutex mutex_;
    
    MtlsStats stats_;
    mutable std::mutex statsMutex_;
    
    bool LoadCertificates();
    bool SetupServerContext();
    bool SetupClientContext();
    static int VerifyCallback(int preverifyOk, void* ctx);
};

// ============================================================================
// Traffic Manager
// ============================================================================

/**
 * Traffic management for canary deployments and A/B testing.
 */
class TrafficManager {
public:
    struct RouteRule {
        std::string name;
        std::string service;
        std::map<std::string, std::string> match;
        std::map<std::string, uint32_t> weights;
        std::optional<std::string> rewrite;
        std::optional<std::string> redirect;
        uint32_t priority;
        bool enabled;
    };
    
    struct CanaryDeployment {
        std::string service;
        std::string stableVersion;
        std::string canaryVersion;
        uint32_t canaryPercentage;
        std::map<std::string, std::string> matchHeaders;
        bool enabled;
    };
    
    struct ABTest {
        std::string name;
        std::string service;
        std::map<std::string, uint32_t> variants;
        std::map<std::string, std::string> matchRules;
        std::chrono::system_clock::time_point startTime;
        std::optional<std::chrono::system_clock::time_point> endTime;
        bool enabled;
    };
    
    explicit TrafficManager();
    
    // Route rules
    void AddRouteRule(const RouteRule& rule);
    void RemoveRouteRule(const std::string& name);
    std::optional<RouteRule> GetRouteRule(const std::string& name) const;
    std::vector<RouteRule> GetRouteRules() const;
    std::optional<RouteRule> MatchRoute(const std::map<std::string, std::string>& headers,
                                              const std::string& path);
    
    // Canary deployments
    void StartCanary(const CanaryDeployment& canary);
    void UpdateCanary(const std::string& service, uint32_t newPercentage);
    void PromoteCanary(const std::string& service);
    void RollbackCanary(const std::string& service);
    std::optional<CanaryDeployment> GetCanary(const std::string& service) const;
    std::vector<CanaryDeployment> GetActiveCanaries() const;
    
    // A/B testing
    void StartABTest(const ABTest& test);
    void StopABTest(const std::string& name);
    std::optional<ABTest> GetABTest(const std::string& name) const;
    std::vector<ABTest> GetActiveABTests() const;
    std::string RouteToVariant(const std::string& testName,
                                const std::string& userId);
    
    // Traffic shifting
    void ShiftTraffic(const std::string& service,
                      const std::string& fromVersion,
                      const std::string& toVersion,
                      uint32_t percentage);
    
    // Fault injection
    void SetFaultInjection(const std::string& service,
                           double delayPercent,
                           std::chrono::milliseconds delayDuration);
    void SetFaultInjection(const std::string& service,
                           double abortPercent,
                           uint32_t abortCode);
    void ClearFaultInjection(const std::string& service);
    
    // Statistics
    struct TrafficStats {
        std::map<std::string, uint64_t> requestsByRoute;
        std::map<std::string, uint64_t> requestsByVersion;
        std::map<std::string, std::map<std::string, uint64_t>> abTestStats;
    };
    TrafficStats GetStats() const;
    void ResetStats();
    
private:
    std::vector<RouteRule> routeRules_;
    std::map<std::string, CanaryDeployment> canaries_;
    std::map<std::string, ABTest> abTests_;
    mutable std::mutex mutex_;
    
    TrafficStats stats_;
    mutable std::mutex statsMutex_;
    
    std::string SelectVersion(const CanaryDeployment& canary,
                               const std::map<std::string, std::string>& headers);
    uint32_t HashUserId(const std::string& userId);
};

// ============================================================================
// Observability
// ============================================================================

/**
 * Observability for service mesh.
 */
class MeshObservability {
public:
    struct Config {
        bool enableAccessLogs;
        bool enableMetrics;
        bool enableTracing;
        std::string accessLogPath;
        std::string metricsEndpoint;
        std::string tracingEndpoint;
        float samplingRate;
    };
    
    struct AccessLogEntry {
        std::chrono::system_clock::time_point timestamp;
        std::string sourceService;
        std::string sourceIp;
        std::string destinationService;
        std::string destinationIp;
        std::string method;
        std::string path;
        std::string protocol;
        uint32_t responseCode;
        uint64_t requestSize;
        uint64_t responseSize;
        std::chrono::milliseconds duration;
        std::string userAgent;
        std::string traceId;
        std::string spanId;
    };
    
    struct MetricValue {
        std::string name;
        double value;
        std::map<std::string, std::string> labels;
        std::chrono::system_clock::time_point timestamp;
    };
    
    explicit MeshObservability(const Config& config);
    
    // Lifecycle
    void Start();
    void Stop();
    bool IsRunning() const;
    
    // Access logging
    void LogAccess(const AccessLogEntry& entry);
    void FlushAccessLogs();
    
    // Metrics
    void RecordRequest(const std::string& sourceService,
                       const std::string& destinationService,
                       const std::string& method,
                       uint32_t responseCode,
                       std::chrono::milliseconds duration);
    void RecordBytes(const std::string& service,
                     uint64_t bytesSent,
                     uint64_t bytesReceived);
    void RecordActiveConnections(const std::string& service, int32_t count);
    std::vector<MetricValue> GetMetrics() const;
    
    // Tracing
    std::string StartSpan(const std::string& operation,
                          const std::optional<std::string>& parentSpanId = std::nullopt);
    void EndSpan(const std::string& spanId);
    void AddSpanTag(const std::string& spanId,
                    const std::string& key,
                    const std::string& value);
    void AddSpanLog(const std::string& spanId,
                    const std::string& message,
                    const std::map<std::string, std::string>& fields);
    void InjectTraceContext(std::map<std::string, std::string>& headers);
    std::optional<std::string> ExtractTraceId(const std::map<std::string, std::string>& headers);
    std::optional<std::string> ExtractSpanId(const std::map<std::string, std::string>& headers);
    
    // Service graph
    struct ServiceEdge {
        std::string source;
        std::string destination;
        uint64_t requestCount;
        double errorRate;
        double latencyP99;
    };
    std::vector<ServiceEdge> GetServiceGraph() const;
    
private:
    Config config_;
    std::atomic<bool> running_;
    
    std::queue<AccessLogEntry> accessLogQueue_;
    mutable std::mutex accessLogMutex_;
    std::thread accessLogThread_;
    
    std::vector<MetricValue> metrics_;
    mutable std::mutex metricsMutex_;
    
    std::map<std::string, std::chrono::system_clock::time_point> activeSpans_;
    mutable std::mutex spansMutex_;
    uint64_t nextSpanId_;
    
    void AccessLogLoop();
    void FlushMetrics();
};

// ============================================================================
// Service Mesh
// ============================================================================

/**
 * Central service mesh controller.
 */
class ServiceMesh {
public:
    struct Config {
        std::string meshId;
        std::string controlPlaneAddress;
        uint16_t controlPlanePort;
        std::string dataPlaneMode;  // sidecar, per-host, shared
        bool enableAutoMtls;
        bool enableAutoInject;
        std::string defaultConfig;
    };
    
    explicit ServiceMesh(const Config& config);
    ~ServiceMesh();
    
    // Lifecycle
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const;
    
    // Sidecar management
    std::shared_ptr<SidecarProxy> CreateSidecar(const ProxyConfig& config);
    void RemoveSidecar(const std::string& instanceId);
    std::shared_ptr<SidecarProxy> GetSidecar(const std::string& instanceId);
    std::vector<std::shared_ptr<SidecarProxy>> GetAllSidecars() const;
    
    // mTLS
    void ConfigureMtls(const MutualTLS::Config& config);
    std::shared_ptr<MutualTLS> GetMtls();
    bool RotateCertificates();
    
    // Traffic management
    void ApplyTrafficPolicy(const TrafficPolicy& policy);
    void RemoveTrafficPolicy(const std::string& name);
    std::shared_ptr<TrafficManager> GetTrafficManager();
    
    // Observability
    void ConfigureObservability(const MeshObservability::Config& config);
    std::shared_ptr<MeshObservability> GetObservability();
    
    // Service discovery integration
    void ConnectToDiscovery(std::shared_ptr<ServiceDiscovery> discovery);
    void SyncWithDiscovery();
    
    // Configuration distribution
    void PushConfig(const std::string& serviceName, const std::string& config);
    void PushConfigToAll(const std::string& config);
    
    // Statistics
    struct MeshStats {
        uint32_t activeSidecars;
        uint64_t totalServices;
        uint64_t totalConnections;
        uint64_t requestsPerSecond;
        double averageLatencyMs;
        double errorRate;
    };
    MeshStats GetStats() const;
    
    // Health check
    bool HealthCheck() const;
    std::map<std::string, bool> GetSidecarHealth() const;
    
private:
    Config config_;
    bool initialized_;
    
    std::map<std::string, std::shared_ptr<SidecarProxy>> sidecars_;
    mutable std::mutex sidecarsMutex_;
    
    std::shared_ptr<MutualTLS> mtls_;
    std::shared_ptr<TrafficManager> trafficManager_;
    std::shared_ptr<MeshObservability> observability_;
    std::shared_ptr<ServiceDiscovery> discovery_;
    
    mutable std::mutex mutex_;
    
    std::thread configSyncThread_;
    std::atomic<bool> stopSync_;
    
    void ConfigSyncLoop();
};

// ============================================================================
// Control Plane
// ============================================================================

/**
 * Service mesh control plane.
 */
class ControlPlane {
public:
    struct Config {
        std::string bindAddress;
        uint16_t port;
        std::string certFile;
        std::string keyFile;
        std::string caFile;
        std::string storageBackend;
        std::string storagePath;
    };
    
    explicit ControlPlane(const Config& config);
    ~ControlPlane();
    
    // Lifecycle
    bool Initialize();
    void Start();
    void Stop();
    bool IsRunning() const;
    
    // API endpoints
    void RegisterSidecar(const std::string& instanceId, const ProxyConfig& config);
    void UnregisterSidecar(const std::string& instanceId);
    ProxyConfig GetSidecarConfig(const std::string& instanceId);
    
    // Certificate management
    std::string IssueCertificate(const std::string& serviceName,
                                  const std::string& spiffeId);
    void RevokeCertificate(const std::string& serialNumber);
    std::vector<std::string> GetActiveCertificates();
    
    // Policy distribution
    void SetTrafficPolicy(const TrafficPolicy& policy);
    void SetSecurityPolicy(const std::string& serviceName,
                           const std::map<std::string, std::string>& policy);
    void SetObservabilityPolicy(const MeshObservability::Config& config);
    
    // Configuration versioning
    uint64_t GetConfigVersion();
    void IncrementConfigVersion();
    
    // xDS API (Envoy Discovery Service)
    void HandleLdsRequest(const std::string& nodeId);  // Listener Discovery
    void HandleCdsRequest(const std::string& nodeId);  // Cluster Discovery
    void HandleEdsRequest(const std::string& nodeId);  // Endpoint Discovery
    void HandleRdsRequest(const std::string& nodeId);  // Route Discovery
    void HandleSdsRequest(const std::string& nodeId);  // Secret Discovery
    
private:
    Config config_;
    std::atomic<bool> running_;
    
    std::map<std::string, ProxyConfig> sidecarConfigs_;
    mutable std::mutex configsMutex_;
    
    uint64_t configVersion_;
    mutable std::mutex versionMutex_;
    
    std::thread serverThread_;
    int serverSocket_;
    
    void ServerLoop();
    void HandleConnection(int clientSocket);
};

} // namespace Gateway
