// RawrXD Health Check System
// Phase R.1: Comprehensive health monitoring and diagnostics
// Kubernetes-compatible health probes with deep system diagnostics

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <atomic>
#include <chrono>
#include <functional>
#include <thread>

namespace RawrXD {
namespace Production {

// Forward declarations
class ObservabilityPlatform;

// Health status levels
enum class HealthStatus {
    HEALTHY,      // All checks passing
    DEGRADED,     // Some checks failing but functional
    UNHEALTHY,    // Critical checks failing
    UNKNOWN       // Status not determined
};

// Health check types
enum class HealthCheckType {
    LIVENESS,     // Is the process running?
    READINESS,    // Is it ready to serve traffic?
    STARTUP,      // Has it finished starting?
    CUSTOM        // Custom application-specific check
};

// Component health
struct ComponentHealth {
    std::string name;
    std::string type;  // "service", "database", "cache", "queue", etc.
    HealthStatus status;
    std::string message;
    std::chrono::steady_clock::time_point lastCheck;
    std::chrono::milliseconds responseTime;
    std::map<std::string, std::string> metadata;
    std::vector<std::string> dependencies;
};

// Health check configuration
struct HealthCheckConfig {
    std::string name;
    HealthCheckType type;
    std::chrono::seconds interval{30};
    std::chrono::seconds timeout{5};
    uint32_t failureThreshold{3};
    uint32_t successThreshold{2};
    bool enabled{true};
    std::vector<std::string> tags;
};

// Health check result
struct HealthCheckResult {
    std::string checkName;
    HealthStatus status;
    std::string message;
    std::chrono::steady_clock::time_point timestamp;
    std::chrono::milliseconds duration;
    std::map<std::string, std::string> details;
    std::exception_ptr error;
};

// System health snapshot
struct SystemHealth {
    HealthStatus overallStatus;
    std::chrono::steady_clock::time_point timestamp;
    std::string version;
    std::string instanceId;
    
    // Component health
    std::vector<ComponentHealth> components;
    
    // Aggregated metrics
    uint32_t healthyComponents;
    uint32_t degradedComponents;
    uint32_t unhealthyComponents;
    
    // System metrics
    double cpuPercent;
    double memoryPercent;
    double diskPercent;
    uint64_t openConnections;
    uint64_t activeThreads;
    
    // Response times
    std::chrono::milliseconds avgResponseTime;
    std::chrono::milliseconds p95ResponseTime;
    std::chrono::milliseconds p99ResponseTime;
};

// Diagnostic test
struct DiagnosticTest {
    std::string id;
    std::string name;
    std::string description;
    std::vector<std::string> categories;  // "network", "storage", "memory", etc.
    std::function<std::map<std::string, std::string>()> execute;
    std::chrono::seconds timeout{60};
    bool isDestructive{false};  // May modify state
};

// Diagnostic result
struct DiagnosticResult {
    std::string testId;
    bool passed;
    std::string message;
    std::chrono::steady_clock::time_point executedAt;
    std::chrono::milliseconds duration;
    std::map<std::string, std::string> findings;
    std::vector<std::string> recommendations;
};

// Health check system
class HealthCheckSystem {
public:
    HealthCheckSystem(ObservabilityPlatform* observability);
    ~HealthCheckSystem();
    
    // Lifecycle
    bool initialize(uint16_t httpPort = 8080);
    bool shutdown();
    bool isInitialized() const { return initialized_; }
    
    // Health check registration
    using HealthCheckFunction = std::function<HealthCheckResult()>;
    bool registerCheck(const HealthCheckConfig& config, HealthCheckFunction check);
    bool unregisterCheck(const std::string& name);
    bool enableCheck(const std::string& name);
    bool disableCheck(const std::string& name);
    
    // Component registration
    bool registerComponent(const ComponentHealth& component);
    bool updateComponentStatus(const std::string& name, HealthStatus status, 
                               const std::string& message);
    bool unregisterComponent(const std::string& name);
    
    // Health queries
    SystemHealth getSystemHealth() const;
    HealthStatus getOverallStatus() const;
    ComponentHealth getComponentHealth(const std::string& name) const;
    std::vector<ComponentHealth> getAllComponents() const;
    std::vector<ComponentHealth> getUnhealthyComponents() const;
    
    // Kubernetes-compatible endpoints
    std::string getLivenessProbe() const;   // HTTP 200 if alive
    std::string getReadinessProbe() const;  // HTTP 200 if ready
    std::string getStartupProbe() const;    // HTTP 200 if started
    std::string getHealthJSON() const;      // Full health JSON
    
    // Diagnostics
    std::string registerDiagnostic(const DiagnosticTest& test);
    DiagnosticResult runDiagnostic(const std::string& testId);
    std::vector<DiagnosticResult> runAllDiagnostics();
    std::vector<DiagnosticResult> runDiagnosticsByCategory(const std::string& category);
    
    // Deep health check
    struct DeepHealthCheck {
        bool passed;
        std::string summary;
        std::vector<DiagnosticResult> results;
        std::chrono::steady_clock::time_point startedAt;
        std::chrono::steady_clock::time_point completedAt;
    };
    DeepHealthCheck runDeepHealthCheck();
    
    // Health history
    std::vector<SystemHealth> getHealthHistory(uint32_t hours) const;
    std::vector<HealthCheckResult> getCheckHistory(const std::string& checkName, 
                                                   uint32_t hours) const;
    
    // Thresholds and alerting
    void setCPUThreshold(double warning, double critical);
    void setMemoryThreshold(double warning, double critical);
    void setDiskThreshold(double warning, double critical);
    void setResponseTimeThreshold(std::chrono::milliseconds warning, 
                                   std::chrono::milliseconds critical);
    
    // Callbacks
    using StatusChangeCallback = std::function<void(const std::string& component, 
                                                    HealthStatus oldStatus, 
                                                    HealthStatus newStatus)>;
    void setStatusChangeCallback(StatusChangeCallback callback);
    
    using HealthAlertCallback = std::function<void(const SystemHealth& health)>;
    void setHealthAlertCallback(HealthAlertCallback callback);

private:
    void healthCheckLoop();
    void metricsCollectionLoop();
    HealthCheckResult executeCheck(const std::string& name);
    void updateOverallStatus();
    SystemHealth collectSystemHealth() const;
    
    std::atomic<bool> running_;
    std::atomic<bool> initialized_;
    std::thread checkThread_;
    std::thread metricsThread_;
    mutable std::mutex mutex_;
    
    ObservabilityPlatform* observability_;
    
    // Registered checks
    std::map<std::string, HealthCheckConfig> checkConfigs_;
    std::map<std::string, HealthCheckFunction> checkFunctions_;
    std::map<std::string, HealthCheckResult> lastResults_;
    std::map<std::string, uint32_t> failureCounts_;
    std::map<std::string, uint32_t> successCounts_;
    
    // Components
    std::map<std::string, ComponentHealth> components_;
    
    // Diagnostics
    std::map<std::string, DiagnosticTest> diagnostics_;
    std::vector<DiagnosticResult> diagnosticHistory_;
    
    // Health history
    std::vector<SystemHealth> healthHistory_;
    
    // Thresholds
    double cpuWarning_ = 70.0;
    double cpuCritical_ = 90.0;
    double memoryWarning_ = 80.0;
    double memoryCritical_ = 95.0;
    double diskWarning_ = 80.0;
    double diskCritical_ = 95.0;
    std::chrono::milliseconds responseTimeWarning_{500};
    std::chrono::milliseconds responseTimeCritical_{2000};
    
    // Callbacks
    StatusChangeCallback statusChangeCallback_;
    HealthAlertCallback healthAlertCallback_;
    
    // HTTP server
    uint16_t httpPort_;
};

// Ready check helper
class ReadyCheck {
public:
    ReadyCheck();
    
    // Signal readiness
    void markReady();
    void markNotReady();
    bool isReady() const { return ready_; }
    
    // Wait for ready
    bool waitForReady(std::chrono::seconds timeout);
    
    // Dependencies
    void addDependency(const std::string& name);
    void markDependencyReady(const std::string& name);
    void markDependencyNotReady(const std::string& name);
    bool areDependenciesReady() const;
    std::vector<std::string> getPendingDependencies() const;
    
private:
    std::atomic<bool> ready_{false};
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    std::map<std::string, bool> dependencies_;
};

// Health check utilities
class HealthCheckUtils {
public:
    // Common health checks
    static HealthCheckResult checkTCPPort(const std::string& host, uint16_t port, 
                                          std::chrono::seconds timeout);
    static HealthCheckResult checkHTTP(const std::string& url, 
                                       std::chrono::seconds timeout);
    static HealthCheckResult checkDatabase(const std::string& connectionString,
                                           std::chrono::seconds timeout);
    static HealthCheckResult checkDiskSpace(const std::string& path, 
                                            double minPercentFree);
    static HealthCheckResult checkMemory(double maxPercentUsed);
    
    // Composite checks
    static HealthCheckResult all(const std::vector<HealthCheckResult>& results);
    static HealthCheckResult any(const std::vector<HealthCheckResult>& results);
};

} // namespace Production
} // namespace RawrXD
