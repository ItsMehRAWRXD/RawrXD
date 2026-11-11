#pragma once

#include "../core/common.hpp"
#include <functional>
#include <chrono>

namespace rawrxd::production {

// Health status
enum class HealthStatus {
    HEALTHY,      // All checks passing
    DEGRADED,     // Some checks failing but operational
    UNHEALTHY     // Critical checks failing
};

// Health check result
struct HealthCheckResult {
    std::string name;
    bool passed;
    std::string message;
    std::chrono::milliseconds duration;
    std::chrono::system_clock::time_point timestamp;
    std::optional<std::string> details;

    HealthCheckResult(const std::string& n, bool p, const std::string& m)
        : name(n), passed(p), message(m), timestamp(std::chrono::system_clock::now()) {}
};

// Health check function type
using HealthCheckFunction = std::function<HealthCheckResult()>;

// Health checker
class HealthChecker {
public:
    HealthChecker();
    ~HealthChecker();

    // Register health check
    void registerCheck(const std::string& name,
                       HealthCheckFunction check,
                       bool critical = false);

    // Unregister health check
    void unregisterCheck(const std::string& name);

    // Run all health checks
    std::vector<HealthCheckResult> runChecks();

    // Run specific check
    HealthCheckResult runCheck(const std::string& name);

    // Get overall health status
    HealthStatus getStatus() const;
    std::string getStatusString() const;

    // Start background monitoring
    void startMonitoring(std::chrono::seconds interval);
    void stopMonitoring();

    // Get last results
    std::vector<HealthCheckResult> getLastResults() const;

    // Set status change callback
    void setStatusCallback(std::function<void(HealthStatus, HealthStatus)> callback);

    // Readiness probe (can accept traffic)
    bool isReady() const;

    // Liveness probe (is alive)
    bool isAlive() const;

    // Startup probe (finished starting)
    bool isStarted() const;

private:
    struct CheckEntry {
        std::string name;
        HealthCheckFunction function;
        bool critical;
        std::optional<HealthCheckResult> last_result;
    };

    std::vector<CheckEntry> checks_;
    mutable std::shared_mutex checks_mutex_;

    std::atomic<HealthStatus> status_{HealthStatus::HEALTHY};
    std::atomic<bool> ready_{false};
    std::atomic<bool> alive_{true};
    std::atomic<bool> started_{false};

    std::thread monitoring_thread_;
    std::atomic<bool> monitoring_{false};
    std::chrono::seconds monitoring_interval_;

    std::function<void(HealthStatus, HealthStatus)> status_callback_;

    void monitoringLoop();
    void updateStatus(const std::vector<HealthCheckResult>& results);
};

// Built-in health checks
namespace health_checks {

// Memory health check
HealthCheckResult checkMemory(uint64_t min_available_mb = 100);

// Disk health check
HealthCheckResult checkDisk(const std::string& path,
                             uint64_t min_available_gb = 1);

// Model loaded check
HealthCheckResult checkModelLoaded(std::shared_ptr<Model> model);

// Inference latency check
HealthCheckResult checkInferenceLatency(std::shared_ptr<Model> model,
                                         std::chrono::milliseconds max_latency);

// Database connection check
HealthCheckResult checkDatabaseConnection(const std::string& connection_string);

// External service check
HealthCheckResult checkExternalService(const std::string& url,
                                        std::chrono::seconds timeout);

// GPU health check
HealthCheckResult checkGPU(int device_id = 0);

// Network connectivity check
HealthCheckResult checkNetwork(const std::string& host, int port);

} // namespace health_checks

// Health check HTTP endpoint
class HealthEndpoint {
public:
    explicit HealthEndpoint(std::shared_ptr<HealthChecker> checker);

    // Get health as JSON
    std::string getHealthJson() const;

    // Get readiness response
    std::string getReadinessResponse() const;

    // Get liveness response
    std::string getLivenessResponse() const;

    // Get startup response
    std::string getStartupResponse() const;

    // HTTP handlers
    std::string handleHealthRequest(const std::string& path) const;

private:
    std::shared_ptr<HealthChecker> checker_;
};

// Metrics exporter for health
class HealthMetricsExporter {
public:
    explicit HealthMetricsExporter(std::shared_ptr<HealthChecker> checker);

    // Export to Prometheus format
    std::string exportPrometheus() const;

    // Export health status
    void exportToPrometheus(std::ostream& out) const;

private:
    std::shared_ptr<HealthChecker> checker_;
};

} // namespace rawrxd::production
